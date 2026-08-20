// Package app assembles a run from a configuration.
//
// It exists so the one-shot CLI and the HTTP handler share one construction
// path: a request served by `fastrecon serve` must be wired exactly like a
// command line invocation, or the two would drift and only one of them would
// be the tested one.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/enumerate"
	"github.com/JoshuaMart/FastRecon/internal/exclude"
	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/portscan"
	"github.com/JoshuaMart/FastRecon/internal/probe"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/resolve"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
	"github.com/JoshuaMart/FastRecon/internal/stage"
)

// ErrRuntime marks a preparation failure that is transient rather than a
// mistake in the configuration: an unreachable resolver list, a health check
// that found nothing usable. Callers map it to an exit code or a status code,
// which is the only signal a scheduler or a caller has.
var ErrRuntime = errors.New("runtime failure")

// App holds what is settled once per process and reused by every run.
//
// The split is not an optimisation. The enumeration engine keys its API keys
// into globally shared source instances, so credentials cannot vary per run
// without one run overwriting another's; resolving them here, once, is what
// makes serving several requests from one process safe.
type App struct {
	cfg      *config.Config
	log      *slog.Logger
	creds    map[string]secrets.Credential
	redactor *secrets.Redactor

	// The resolver pool is loaded and health-checked on first use, then kept:
	// re-checking a public resolver list on every request would cost more than
	// the run it serves. A failure is not cached — it is usually the network.
	poolMu       sync.Mutex
	pool         []string
	poolWarnings []string
}

// New settles the process-level configuration.
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	if cfg == nil || log == nil {
		return nil, errors.New("app: configuration and logger are required")
	}

	a := &App{cfg: cfg, log: log}
	a.creds = a.resolveCredentials()
	a.redactor = secrets.NewRedactor(a.creds)

	// Published to the environment here, once: it is the only channel the
	// enumeration engine reads, and it is process-global either way.
	if err := secrets.Export(a.creds); err != nil {
		return nil, err
	}
	return a, nil
}

// Redactor returns the process redactor, so a caller can scrub a rendered
// report before it leaves the process.
func (a *App) Redactor() *secrets.Redactor { return a.redactor }

// Config returns the process-level configuration.
func (a *App) Config() *config.Config { return a.cfg }

// Run executes one pipeline against runCfg, which may be the process
// configuration or a per-request copy of it.
func (a *App) Run(ctx context.Context, runCfg *config.Config) (*report.Report, error) {
	stages, err := a.buildStages(ctx, runCfg)
	if err != nil {
		return nil, err
	}
	return pipeline.New(runCfg, stages, a.log).Run(ctx)
}

// resolveCredentials resolves the source keys for every source that may be
// queried.
func (a *App) resolveCredentials() map[string]secrets.Credential {
	resolver, err := secrets.NewResolver(a.cfg.ProviderConfig)
	if err != nil {
		// A provider config that cannot be read is reported by the stage that
		// needs it; a run without keys is still a run.
		a.log.Warn("provider config unusable", "error", err)
		return nil
	}

	// Cloned: appending to cfg.Sources would write into its backing array
	// whenever it has spare capacity.
	wanted := slices.Clone(a.cfg.Sources)
	if a.cfg.AllSources {
		for _, s := range enumerate.Available() {
			wanted = append(wanted, s.Name)
		}
		slices.Sort(wanted)
		wanted = slices.Compact(wanted)
	}

	creds := resolver.Resolve(wanted)
	// Reported against every source that will be queried, not just the
	// default five: under --all-sources the two differ completely.
	inv := secrets.Take(wanted, creds)
	for source, origin := range inv.Configured {
		a.log.Debug("source credential", "source", source, "origin", origin)
	}
	a.log.Info("credentials resolved", "configured", len(inv.Configured), "missing", inv.Missing)
	return creds
}

// buildStages wires the stage implementations the scope calls for.
func (a *App) buildStages(ctx context.Context, cfg *config.Config) (pipeline.Stages, error) {
	enumerator, err := enumerate.NewSubfaster(enumerate.Options{
		Sources:        a.cfg.Sources,
		ExcludeSources: a.cfg.ExcludeSources,
		All:            a.cfg.AllSources,
		SourceTimeout:  a.cfg.SourceTimeout,
		Credentials:    a.creds,
		Redactor:       a.redactor,
		Logger:         a.log,
	})
	if err != nil {
		return pipeline.Stages{}, err
	}

	excluder, err := exclude.New(cfg.Exclude, cfg.ExcludeStrictWildcard)
	if err != nil {
		return pipeline.Stages{}, fmt.Errorf("invalid exclusions:\n%w", err)
	}

	stages := pipeline.Stages{Enumerator: enumerator, Excluder: excluder}

	// Built only when the scope reaches it: a resolver constructed for an
	// enumeration-only run would open sockets nothing asked for.
	if cfg.Scope.Includes(stage.Resolve) {
		resolvers, warnings, err := a.resolverPool(ctx)
		if err != nil {
			return pipeline.Stages{}, err
		}
		cfg.Warnings = append(cfg.Warnings, warnings...)

		resolver, err := resolve.New(resolve.Options{
			Domain:         cfg.Domain,
			Resolvers:      resolvers,
			Concurrency:    a.cfg.ResolverConcurrency,
			Retries:        a.cfg.ResolverRetries,
			Timeout:        a.cfg.ResolverTimeout,
			WildcardProbes: a.cfg.WildcardProbes,
			Logger:         a.log,
		})
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.Resolver = resolver
	}

	if cfg.Scope.Includes(stage.PortScan) {
		scanner, err := portscan.New(portscan.Options{
			Mode:         a.cfg.ScanMode,
			Ports:        cfg.Ports,
			ExcludePorts: cfg.ExcludePorts,
			SkipCDN:      cfg.SkipCDN,
			Concurrency:  a.cfg.ScanConcurrency,
			Rate:         a.cfg.ScanRate,
			Retries:      a.cfg.ScanRetries,
			Timeout:      a.cfg.ScanTimeout,
			Logger:       a.log,
		})
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.PortScanner = scanner
	}

	if cfg.Scope.Includes(stage.HTTPProbe) {
		prober, err := probe.New(probe.Options{
			Concurrency:     a.cfg.ProbeConcurrency,
			Rate:            a.cfg.ProbeRate,
			Timeout:         a.cfg.ProbeTimeout,
			Retries:         a.cfg.ProbeRetries,
			FollowRedirects: a.cfg.ProbeFollowRedirects,
			MaxRedirects:    a.cfg.ProbeMaxRedirects,
			UserAgent:       a.cfg.ProbeUserAgent,
			Headers:         a.cfg.ProbeHeaders,
			Logger:          a.log,
		})
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.Prober = prober
	}

	return stages, nil
}

// resolverPool assembles the resolver list once and, unless told otherwise,
// removes the resolvers that cannot be trusted to answer correctly.
func (a *App) resolverPool(ctx context.Context) (resolvers, warnings []string, err error) {
	a.poolMu.Lock()
	defer a.poolMu.Unlock()

	if a.pool != nil {
		return a.pool, a.poolWarnings, nil
	}

	resolvers, err = resolve.LoadResolvers(ctx, resolve.LoadOptions{
		Inline: a.cfg.Resolvers,
		File:   a.cfg.ResolversFile,
		URL:    a.cfg.ResolversURL,
		Logger: a.log,
	})
	if err != nil {
		// Fetching a list over the network can fail for reasons that have
		// nothing to do with the configuration being wrong.
		if a.cfg.ResolversURL != "" {
			return nil, nil, fmt.Errorf("%w: %w", ErrRuntime, err)
		}
		return nil, nil, err
	}
	a.log.Info("resolvers loaded", "count", len(resolvers))

	if a.cfg.ValidateResolvers {
		health := resolve.CheckResolvers(ctx, resolvers, resolve.HealthOptions{
			Budget:      a.cfg.ResolverHealthBudget,
			Timeout:     a.cfg.ResolverTimeout,
			Concurrency: a.cfg.ResolverConcurrency,
			Logger:      a.log,
		})
		if len(health.Good) == 0 {
			return nil, nil, fmt.Errorf("%w: every one of the %d configured resolvers failed the health check", ErrRuntime, len(resolvers))
		}
		// These reach the report, not just the log: a resolution done through
		// a pool that lost half its members is a result worth qualifying.
		if len(health.Dropped) > 0 {
			warnings = append(warnings, fmt.Sprintf("%d of %d resolvers dropped by the health check", len(health.Dropped), len(resolvers)))
		}
		if health.Unchecked > 0 {
			warnings = append(warnings, fmt.Sprintf("%d of %d resolvers were kept unchecked: the health budget ran out", health.Unchecked, len(resolvers)))
		}
		resolvers = health.Good
	}

	a.pool, a.poolWarnings = resolvers, warnings
	return resolvers, warnings, nil
}
