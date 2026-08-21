// Package resolve separates DNS-answering hosts from non-answering ones (dnsx-backed, serverless-compatible).
package resolve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/retryabledns"

	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/report"
)

// Options configures the resolver.
type Options struct {
	Domain         string        // run root (always probed for wildcards)
	Resolvers      []string
	Concurrency    int
	Retries        int
	Timeout        time.Duration
	WildcardProbes int            // random names per domain to detect wildcard records
	Logger         *slog.Logger
}

// DNSX is the dnsx-backed Resolver.
type DNSX struct {
	opts  Options
	query func(host string) (*retryabledns.DNSData, error) // testable DNS query entry point
}

// New builds the resolver.
func New(opts Options) (*DNSX, error) {
	switch {
	case opts.Logger == nil:
		return nil, errors.New("resolve: logger is required")
	case opts.Domain == "":
		return nil, errors.New("resolve: domain is required")
	case opts.Concurrency < 1:
		return nil, errors.New("resolve: concurrency must be at least 1")
	case opts.Timeout <= 0:
		return nil, errors.New("resolve: timeout must be positive")
	case opts.WildcardProbes < 1:
		return nil, errors.New("resolve: wildcard probes must be at least 1")
	case opts.Retries < 0:
		return nil, errors.New("resolve: retries must not be negative")
	}

	resolvers := opts.Resolvers
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}

	client, err := dnsx.New(dnsx.Options{
		BaseResolvers: resolvers,
		MaxRetries:    opts.Retries + 1, // engine counts total, not extra; zero retries = one attempt
		Timeout:       opts.Timeout,
		QuestionTypes: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME},
	})
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	opts.Resolvers = resolvers
	return &DNSX{opts: opts, query: client.QueryMultiple}, nil
}

// Name identifies the stage implementation.
func (r *DNSX) Name() string { return "dnsx" }

// Resolve classifies every host as live, dead or a wildcard artifact.
//
// Nothing is dropped: a host that does not resolve stays in the report with
// the reason it failed, because a dangling CNAME or a vanished host is a
// finding in its own right.
func (r *DNSX) Resolve(ctx context.Context, hosts []string) (pipeline.Resolution, error) {
	var out pipeline.Resolution
	if len(hosts) == 0 {
		return out, nil
	}

	r.opts.Logger.Debug("resolution started",
		"hosts", len(hosts),
		"resolvers", r.opts.Resolvers,
		"concurrency", r.opts.Concurrency,
	)

	// Wildcards are established first: without them a single wildcard record
	// turns thousands of junk names into apparently live hosts.
	wc := r.detectWildcards(ctx, hosts)
	if len(wc.byParent) > 0 {
		parents := make([]string, 0, len(wc.byParent))
		for p := range wc.byParent {
			parents = append(parents, p)
		}
		out.Warnings = append(out.Warnings, fmt.Sprintf("wildcard dns on %s: matching hosts are reported as wildcard, not live", strings.Join(parents, ", ")))
	}

	results := make([]report.Host, len(hosts))
	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, r.opts.Concurrency)
		mu        sync.Mutex
		unchecked int
	)

	for i, host := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				// Out of time before this host was even started: report it as
				// discovered but unresolved rather than inventing a verdict.
				results[i] = report.Host{Host: host, Status: report.StatusDiscovered}
				mu.Lock()
				unchecked++
				mu.Unlock()
				return
			}
			if ctx.Err() != nil {
				results[i] = report.Host{Host: host, Status: report.StatusDiscovered}
				mu.Lock()
				unchecked++
				mu.Unlock()
				return
			}
			results[i] = r.resolveOne(host, wc)
		}(i, host)
	}
	wg.Wait()

	out.Hosts = results
	if unchecked > 0 {
		out.Truncated = true
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d of %d hosts were not resolved before the stage deadline", unchecked, len(hosts)))
	}
	return out, nil
}

// resolveOne queries a single host and turns the answer into a verdict.
func (r *DNSX) resolveOne(host string, wc *wildcards) report.Host {
	out := report.Host{Host: host}

	data, err := r.query(host)
	switch {
	case err != nil:
		out.Status = report.StatusDead
		out.Reason = report.ReasonTimeout
		return out
	case data == nil:
		out.Status = report.StatusDead
		out.Reason = report.ReasonNoAnswer
		return out
	}

	addresses, cnames := answersOf(data)
	out.Addresses = addresses
	out.CNAME = cnames

	if parent, covered := wc.covers(host, addresses, cnames); covered {
		out.Status = report.StatusWildcard
		out.Reason = report.ReasonWildcard
		r.opts.Logger.Debug("wildcard artifact", "host", host, "parent", parent)
		return out
	}

	switch {
	case len(addresses) > 0:
		out.Status = report.StatusLive
	case strings.EqualFold(data.StatusCode, "NXDOMAIN"):
		out.Status = report.StatusDead
		out.Reason = report.ReasonNXDomain
	default:
		// No address, but a CNAME: a dangling alias, which is exactly the kind
		// of thing this stage exists to surface.
		out.Status = report.StatusDead
		out.Reason = report.ReasonNoAnswer
	}
	return out
}

// answersOf extracts the addresses and aliases from a DNS answer.
func answersOf(data *retryabledns.DNSData) (addresses, cnames []string) {
	addresses = make([]string, 0, len(data.A)+len(data.AAAA))
	addresses = append(addresses, data.A...)
	addresses = append(addresses, data.AAAA...)
	for _, c := range data.CNAME {
		if n := normalizeName(c); n != "" {
			cnames = append(cnames, n)
		}
	}
	if len(addresses) == 0 {
		addresses = nil
	}
	return addresses, cnames
}
