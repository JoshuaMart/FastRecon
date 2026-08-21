// Package portscan finds open ports of live hosts using TCP connect.
// (naabu discarded: requires dynamic linking + SYN mode needs root)
package portscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/projectdiscovery/cdncheck"

	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/ratelimit"
	"github.com/JoshuaMart/FastRecon/internal/report"
)

// Scan modes.
const (
	ModeConnect = "connect"
	ModeSYN     = "syn"
)

// Options configures the port scanner.
type Options struct {
	Mode         string
	Ports        string
	ExcludePorts string
	// SkipCDN limits CDN and WAF addresses to the standard web ports. It does
	// not affect detection, which always runs.
	SkipCDN     bool
	Concurrency int
	Rate        int
	Retries     int
	Timeout     time.Duration
	// CDN is the address-range dataset to classify against. Loading it costs
	// ~13ms and ~9MB, and it takes no option, so a caller running several
	// scans passes one instance rather than paying per scan. Nil loads a
	// private one, which is what a standalone use of this package wants.
	CDN    *cdncheck.Client
	Logger *slog.Logger
}

// Scanner is the built-in PortScanner.
type Scanner struct {
	opts  Options
	ports portSpec
	cdn   *cdncheck.Client
	// scan allows testing planning/batching/mapping without network access.
	scan func(ctx context.Context, addresses []string, ports portSpec, limiter *ratelimit.Limiter) (scanResult, error)
}

// New validates the options and prepares the scanner.
func New(opts Options) (*Scanner, error) {
	if opts.Logger == nil {
		return nil, errors.New("portscan: logger is required")
	}
	if opts.Concurrency < 1 || opts.Rate < 1 {
		return nil, errors.New("portscan: concurrency and rate must be at least 1")
	}
	if opts.Timeout <= 0 {
		return nil, errors.New("portscan: timeout must be positive")
	}

	ports, err := parsePorts(opts.Ports)
	if err != nil {
		return nil, fmt.Errorf("portscan: %w", err)
	}
	if opts.ExcludePorts != "" {
		if err := validatePortExpression(opts.ExcludePorts); err != nil {
			return nil, fmt.Errorf("portscan: exclude-%w", err)
		}
	}

	// SYN mode refused (not silently downgraded); missing results would mimic a closed host.
	if opts.Mode == ModeSYN {
		return nil, errors.New("portscan: syn mode is not available in this build; it needs raw sockets, which the serverless and container deployments do not grant. Use --scan-mode=connect")
	}
	if opts.Mode != ModeConnect {
		return nil, fmt.Errorf("portscan: unknown scan mode %q", opts.Mode)
	}

	cdn := opts.CDN
	if cdn == nil {
		cdn = cdncheck.New()
	}

	s := &Scanner{opts: opts, ports: ports, cdn: cdn}
	s.scan = s.scanConnect
	return s, nil
}

// Name identifies the stage implementation.
func (s *Scanner) Name() string { return "connect" }

// Scan finds open ports of live hosts (dead hosts/wildcards would waste budget on known facts).
func (s *Scanner) Scan(ctx context.Context, hosts []report.Host) (pipeline.PortScan, error) {
	out := pipeline.PortScan{Hosts: hosts}

	// Limiter on the run, not the scanner: a stopped limiter's Wait returns
	// immediately, so a reused instance would lose its rate limit from the
	// second run on. Shared across both passes so --scan-rate describes total.
	limiter := ratelimit.New(s.opts.Rate)
	defer limiter.Stop()

	// Index by address (dedup: one scan per address, not per subdomain).
	byAddress := indexAddresses(hosts)
	if len(byAddress) == 0 {
		s.opts.Logger.Info("port scan skipped", "reason", "no live host with an address")
		return out, nil
	}

	addresses := sortedKeys(byAddress)
	edges := classify(s.cdn, addresses)
	plain, behindEdge := splitByEdge(addresses, edges, s.opts.SkipCDN)

	s.opts.Logger.Debug("port scan planned",
		"addresses", len(addresses),
		"behind_cdn", len(edges),
		"mode", s.opts.Mode,
		"ports", s.ports.String(),
		"limited_addresses", len(behindEdge),
	)

	open := map[string][]int{}
	tally := map[string]*report.Scan{}
	var truncated bool

	if len(plain) > 0 {
		found, err := s.scan(ctx, plain, s.ports, limiter)
		if err != nil {
			return out, err
		}
		merge(open, found.open)
		mergeTally(tally, found.tally)
	}
	if len(behindEdge) > 0 {
		// CDN restricted pass: edge serves thousands of customers, full port list describes provider, not target.
		found, err := s.scan(ctx, behindEdge, portSpec{List: joinPorts(cdnPorts)}, limiter)
		if err != nil {
			return out, err
		}
		merge(open, found.open)
		mergeTally(tally, found.tally)
	}
	if ctx.Err() != nil {
		truncated = true
		out.Warnings = append(out.Warnings, "port scan cut short by its deadline, open ports may be missing")
	}

	out.Hosts = s.attach(hosts, byAddress, edges, open, tally)
	out.Truncated = truncated
	if len(edges) > 0 && s.opts.SkipCDN {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d address(es) behind a CDN or WAF were scanned for ports %s only", len(behindEdge), joinPorts(cdnPorts)))
	}
	return out, nil
}

// attach maps per-address results back to all hosts resolving to each address + CDN flags.
func (s *Scanner) attach(hosts []report.Host, byAddress map[string][]int, edges map[string]edge, open map[string][]int, tally map[string]*report.Scan) []report.Host {
	out := make([]report.Host, len(hosts))
	copy(out, hosts)

	// Invert mapping: addresses per host index.
	hostAddresses := make(map[int][]string, len(hosts))
	for addr, indexes := range byAddress {
		for _, i := range indexes {
			hostAddresses[i] = append(hostAddresses[i], addr)
		}
	}

	for i := range out {
		addrs, ok := hostAddresses[i]
		if !ok {
			continue
		}
		sort.Strings(addrs)

		limited := false
		// Track which addresses each port was found on (multi-address hosts record all).
		sources := map[int][]string{}
		var ports []int
		for _, addr := range addrs {
			if _, behind := edges[addr]; behind && s.opts.SkipCDN {
				limited = true
			}
			for _, p := range open[addr] {
				if _, seen := sources[p]; !seen {
					ports = append(ports, p)
				}
				sources[p] = append(sources[p], addr)
			}
		}
		sort.Ints(ports)

		out[i].Ports = make([]report.Port, 0, len(ports))
		for _, p := range ports {
			found := sources[p]
			sort.Strings(found)
			out[i].Ports = append(out[i].Ports, report.Port{
				Port:      p,
				Protocol:  "tcp",
				State:     "open",
				Addresses: found,
			})
		}
		if len(out[i].Ports) == 0 {
			out[i].Ports = nil
		}
		out[i].CDN = cdnEntries(addrs, edges, limited)
		// Summed over the host's addresses: what this host was probed for.
		out[i].Scan = sumTally(addrs, tally)
	}
	return out
}

// indexAddresses maps scannable addresses to their host indices.
func indexAddresses(hosts []report.Host) map[string][]int {
	out := map[string][]int{}
	for i, h := range hosts {
		if h.Status != report.StatusLive {
			continue
		}
		for _, addr := range h.Addresses {
			if net.ParseIP(addr) == nil {
				continue
			}
			out[addr] = append(out[addr], i)
		}
	}
	return out
}

// splitByEdge separates full port sweep addresses from CDN addresses, which get cdnPorts only.
func splitByEdge(addresses []string, edges map[string]edge, skipCDN bool) (plain, behindEdge []string) {
	for _, addr := range addresses {
		if _, behind := edges[addr]; behind && skipCDN {
			behindEdge = append(behindEdge, addr)
			continue
		}
		plain = append(plain, addr)
	}
	return plain, behindEdge
}

// mergeTally folds one pass's counters into the run's.
func mergeTally(dst, src map[string]*report.Scan) {
	for addr, t := range src {
		d := dst[addr]
		if d == nil {
			d = &report.Scan{}
			dst[addr] = d
		}
		d.Scanned += t.Scanned
		d.Open += t.Open
		d.Refused += t.Refused
		d.Filtered += t.Filtered
		d.Unknown += t.Unknown
	}
}

// sumTally totals a host's addresses, returning nil when none was probed so
// the field stays absent rather than reading as an empty sweep.
func sumTally(addrs []string, tally map[string]*report.Scan) *report.Scan {
	var out *report.Scan
	for _, a := range addrs {
		t := tally[a]
		if t == nil {
			continue
		}
		if out == nil {
			out = &report.Scan{}
		}
		out.Scanned += t.Scanned
		out.Open += t.Open
		out.Refused += t.Refused
		out.Filtered += t.Filtered
		out.Unknown += t.Unknown
	}
	return out
}

func merge(dst, src map[string][]int) {
	for k, v := range src {
		dst[k] = append(dst[k], v...)
	}
}

func sortedKeys(m map[string][]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
