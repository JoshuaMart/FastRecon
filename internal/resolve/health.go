package resolve

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

// Health-check anchors: positive anchors (known answers, to catch liars) +
// a negative anchor (a name that cannot exist, to catch NXDOMAIN hijacking).
const (
	healthNegativeTLD     = "com"
	defaultHealthWorkers  = 200
	healthQueryMaxTimeout = 3 * time.Second
)

// healthAnchors are names whose published addresses are stable and widely
// known, so a resolver answering something else is answering for someone.
//
// There are three, from three operators: a single anchor is one operator's
// decision away from failing every resolver in the pool. They are consulted in
// order and the first correct answer settles it, so the common case costs one
// query.
var healthAnchors = []struct {
	name      string
	addresses []string
}{
	{"one.one.one.one", []string{"1.1.1.1", "1.0.0.1"}},
	{"dns.google", []string{"8.8.8.8", "8.8.4.4"}},
	{"dns.quad9.net", []string{"9.9.9.9", "149.112.112.112"}},
}

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
	Budget      time.Duration // bounds the pass; unreached resolvers are counted, not discarded
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

// CheckResolvers removes untrustworthy resolvers (published lists validated elsewhere; network+filtering may differ).
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
	// Pre-filled as unchecked: a resolver the budget never reached is kept,
	// not dropped.
	outcomes := make([]outcome, len(resolvers))
	for i, resolver := range resolvers {
		outcomes[i] = outcome{resolver: resolver}
	}

	workers(budgetCtx, len(resolvers), opts.Concurrency, func(i int) {
		outcomes[i] = outcome{resolver: resolvers[i], reason: checkOne(resolvers[i], timeout), checked: true}
	})

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

	// No response at all means the resolver is unreachable: asking about more
	// names only costs more timeouts, which on a list of thousands is the
	// whole health budget. A response with no address means the anchor is the
	// problem, so try the next one.
	//
	// A resolver is only called a liar when every anchor that gave it a chance
	// came back with addresses nobody publishes.
	correct, wrong := 0, 0
	for _, anchor := range healthAnchors {
		positive, err := client.Query(anchor.name, dns.TypeA)
		if err != nil {
			return dropUnreachable
		}
		if positive == nil || len(positive.A) == 0 {
			continue
		}
		if slices.ContainsFunc(positive.A, func(a string) bool { return slices.Contains(anchor.addresses, a) }) {
			correct++
			break
		}
		wrong++
	}
	switch {
	case correct > 0:
		// Honest about a known name: settled.
	case wrong > 0:
		return dropLying
	default:
		// Every anchor answered without an address: no verdict about the
		// resolver, so not a liar.
		return dropUnreachable
	}

	negative, err := client.Query(randomLabel()+"."+healthNegativeTLD, dns.TypeA)
	if err != nil {
		// Answered the first query but not the second: flaky, not malicious.
		// It stays; the run's own retries absorb it.
		return ""
	}
	if negative != nil && len(negative.A) > 0 {
		return dropHijacker
	}
	return ""
}
