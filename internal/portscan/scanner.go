// Package portscan finds the open ports of the live hosts.
//
// The scanner is a built-in TCP connect scanner. naabu was the intended
// engine, but it reaches libc through purego to batch raw sends, which forces
// a dynamically linked binary — one that cannot start in the distroless
// static image every deployment here is built on. The only thing it offered
// beyond this scanner was SYN mode, which needs privileges the target
// environment does not grant anyway.
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
	Logger      *slog.Logger
}

// Scanner is the built-in PortScanner.
type Scanner struct {
	opts  Options
	ports portSpec
	cdn   *cdncheck.Client
	// scan is the single point where sockets are opened. It is a field so the
	// planning, batching and result-mapping logic can be tested without
	// touching the network.
	scan func(ctx context.Context, addresses []string, ports portSpec, limiter *ratelimit.Limiter) (map[string][]int, error)
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

	// SYN mode is refused rather than silently downgraded: a SYN scan the
	// process cannot perform finds no open ports at all, which reads exactly
	// like a host with nothing listening.
	if opts.Mode == ModeSYN {
		return nil, errors.New("portscan: syn mode is not available in this build; it needs raw sockets, which the serverless and container deployments do not grant. Use --scan-mode=connect")
	}
	if opts.Mode != ModeConnect {
		return nil, fmt.Errorf("portscan: unknown scan mode %q", opts.Mode)
	}

	s := &Scanner{opts: opts, ports: ports, cdn: cdncheck.New()}
	s.scan = s.scanConnect
	return s, nil
}

// Name identifies the stage implementation.
func (s *Scanner) Name() string { return "connect" }

// Scan finds the open ports of every live host.
//
// Only live hosts are scanned. A dead host has no address to connect to, and
// a wildcard artifact is not a host at all — scanning either would spend the
// budget proving something already known.
func (s *Scanner) Scan(ctx context.Context, hosts []report.Host) (pipeline.PortScan, error) {
	out := pipeline.PortScan{Hosts: hosts}

	// The limiter belongs to the run, not to the scanner. Holding it on the
	// scanner and stopping it here left a reused instance with a stopped
	// limiter, whose Wait returns immediately — the second run of a warm
	// process would silently lose its rate limit entirely.
	//
	// One limiter for both passes: one per pass would hand the full
	// configured rate to each, so --scan-rate would not describe the run.
	limiter := ratelimit.New(s.opts.Rate)
	defer limiter.Stop()

	// Several subdomains commonly resolve to one address; scanning it once
	// and mapping the result back is the difference between one scan and
	// fifty identical ones.
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
	var truncated bool

	if len(plain) > 0 {
		found, err := s.scan(ctx, plain, s.ports, limiter)
		if err != nil {
			return out, err
		}
		merge(open, found)
	}
	if len(behindEdge) > 0 {
		// The restricted pass: a CDN edge answers for thousands of unrelated
		// customers, so its full port list describes the provider, not this
		// target.
		found, err := s.scan(ctx, behindEdge, portSpec{List: joinPorts(cdnPorts)}, limiter)
		if err != nil {
			return out, err
		}
		merge(open, found)
	}
	if ctx.Err() != nil {
		truncated = true
		out.Warnings = append(out.Warnings, "port scan cut short by its deadline, open ports may be missing")
	}

	out.Hosts = s.attach(hosts, byAddress, edges, open)
	out.Truncated = truncated
	if len(edges) > 0 && s.opts.SkipCDN {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d address(es) behind a CDN or WAF were scanned for ports %s only", len(behindEdge), joinPorts(cdnPorts)))
	}
	return out, nil
}

// attach maps the per-address results back onto every host that resolves to
// that address, and records the CDN determination.
func (s *Scanner) attach(hosts []report.Host, byAddress map[string][]int, edges map[string]edge, open map[string][]int) []report.Host {
	out := make([]report.Host, len(hosts))
	copy(out, hosts)

	// Invert: which addresses belong to each host index.
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
		// Which addresses each port was found on, so a port shared by several
		// of a host's addresses records all of them.
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
	}
	return out
}

// indexAddresses maps every scannable address to the hosts that resolve to it.
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

// splitByEdge separates the addresses that get the full port sweep from those
// restricted to the web ports.
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
