package resolve

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

// Health-check anchors.
//
// The positive anchor is a name with a well-known, stable answer, so a
// resolver can be caught lying rather than merely being reachable. The
// negative anchor is a random name that must not exist: a resolver answering
// it with an address hijacks NXDOMAIN, which would turn every dead host in
// the report into a live one.
const (
	healthAnchor          = "one.one.one.one"
	healthNegativeTLD     = "com"
	defaultHealthWorkers  = 200
	healthQueryMaxTimeout = 3 * time.Second
)

var healthAnchorAddresses = []string{"1.1.1.1", "1.0.0.1"}

// Dropped records a resolver removed from the pool and why.
type Dropped struct {
	Resolver string
	Reason   string
}

// Drop reasons.
const (
	dropUnreachable = "no usable answer"
	dropLying       = "wrong answer for a known name"
	dropHijacker    = "hijacks NXDOMAIN"
)

// HealthOptions configures the validation pass.
type HealthOptions struct {
	// Budget bounds the whole pass. Resolvers not reached within it are kept
	// unchecked and counted, never silently discarded.
	Budget      time.Duration
	Timeout     time.Duration
	Concurrency int
	Logger      *slog.Logger
}

// HealthResult is the outcome of validating a resolver pool.
type HealthResult struct {
	Good      []string
	Dropped   []Dropped
	Unchecked int
	Duration  time.Duration
}

// CheckResolvers removes the resolvers that cannot be trusted to answer
// correctly.
//
// This matters most for the large published lists: they are validated for
// reachability by whoever publishes them, from wherever their validator runs,
// which says nothing about reachability from inside this job's network, nor
// about filtering or NXDOMAIN redirection.
func CheckResolvers(ctx context.Context, resolvers []string, opts HealthOptions) HealthResult {
	start := time.Now()
	res := HealthResult{}
	if len(resolvers) == 0 {
		return res
	}

	if opts.Concurrency < 1 {
		opts.Concurrency = defaultHealthWorkers
	}
	timeout := min(opts.Timeout, healthQueryMaxTimeout)
	if timeout <= 0 {
		timeout = healthQueryMaxTimeout
	}

	budgetCtx := ctx
	if opts.Budget > 0 {
		var cancel context.CancelFunc
		budgetCtx, cancel = context.WithTimeout(ctx, opts.Budget)
		defer cancel()
	}

	type outcome struct {
		resolver string
		reason   string
		checked  bool
	}
	outcomes := make([]outcome, len(resolvers))

	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, opts.Concurrency)
	)
	for i, resolver := range resolvers {
		wg.Add(1)
		go func(i int, resolver string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-budgetCtx.Done():
				outcomes[i] = outcome{resolver: resolver}
				return
			}
			if budgetCtx.Err() != nil {
				outcomes[i] = outcome{resolver: resolver}
				return
			}
			outcomes[i] = outcome{resolver: resolver, reason: checkOne(resolver, timeout), checked: true}
		}(i, resolver)
	}
	wg.Wait()

	for _, o := range outcomes {
		switch {
		case !o.checked:
			res.Unchecked++
			res.Good = append(res.Good, o.resolver)
		case o.reason == "":
			res.Good = append(res.Good, o.resolver)
		default:
			res.Dropped = append(res.Dropped, Dropped{Resolver: o.resolver, Reason: o.reason})
		}
	}
	res.Duration = time.Since(start)

	opts.Logger.Info("resolver health check",
		"checked", len(resolvers)-res.Unchecked,
		"kept", len(res.Good),
		"dropped", len(res.Dropped),
		"unchecked", res.Unchecked,
		"duration_ms", res.Duration.Milliseconds(),
	)
	for _, d := range res.Dropped {
		opts.Logger.Debug("resolver dropped", "resolver", d.Resolver, "reason", d.Reason)
	}
	return res
}

// checkOne is the per-resolver probe. It is a variable so the surrounding
// budget and accounting logic can be tested without touching the network.
var checkOne = checkResolver

// checkResolver returns the reason a resolver is unusable, or "" if it is fine.
func checkResolver(resolver string, timeout time.Duration) string {
	client, err := retryabledns.NewWithOptions(retryabledns.Options{
		BaseResolvers: []string{resolver},
		MaxRetries:    1,
		Timeout:       timeout,
	})
	if err != nil {
		return dropUnreachable
	}

	positive, err := client.Query(healthAnchor, dns.TypeA)
	if err != nil || positive == nil || len(positive.A) == 0 {
		return dropUnreachable
	}
	if !slices.ContainsFunc(positive.A, func(a string) bool { return slices.Contains(healthAnchorAddresses, a) }) {
		return dropLying
	}

	negative, err := client.Query(randomLabel()+"."+healthNegativeTLD, dns.TypeA)
	if err != nil {
		// A resolver that answered the first query but not the second is
		// flaky rather than malicious; it stays, and the run's own retries
		// absorb it.
		return ""
	}
	if negative != nil && len(negative.A) > 0 {
		return dropHijacker
	}
	return ""
}
