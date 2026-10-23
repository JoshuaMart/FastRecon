// Package app assembles a run from a configuration.
//
// The one-shot CLI and the HTTP handler share one construction path so a
// request served by `fastrecon serve` is wired exactly like a command line run.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/projectdiscovery/cdncheck"

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

// ErrRuntime marks transient failures (unreachable resolvers, health check failures).
var ErrRuntime = errors.New("runtime failure")

// App holds process-level config (not an optimization; credentials are process-global for safety).
type App struct {
	cfg      *config.Config
	log      *slog.Logger
	creds    map[string]secrets.Credential
	redactor *secrets.Redactor

	// Resolver pool cached after first load (failures not cached; usually network).
	poolMu       sync.Mutex
	pool         []string
	poolWarnings []string
	poolDegraded []string

	// Engine cache. The CDN address ranges and technology fingerprints cost
	// ~130ms and ~110MB of retained heap to build, and their options are
	// process-level, so they are built once and shared. Rebuilding per run
	// ran a 256MB function instance out of memory.
	engineMu sync.Mutex
	cdn      *cdncheck.Client
	prober   *probe.HTTPX
}

// New settles the process-level configuration.
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	if cfg == nil || log == nil {
		return nil, errors.New("app: configuration and logger are required")
	}

	a := &App{cfg: cfg, log: log}
	a.creds = a.resolveCredentials()
	a.redactor = secrets.NewRedactor(a.creds)

	// Export to environment once (enumeration engine reads process-global values).
	if err := secrets.Export(a.creds); err != nil {
		return nil, err
	}
	return a, nil
}

// Redactor returns the process redactor for scrubbing reports.
func (a *App) Redactor() *secrets.Redactor { return a.redactor }

// Config returns the process-level configuration.
func (a *App) Config() *config.Config { return a.cfg }

// Run executes one pipeline against runCfg, which may be the process
// configuration or a per-request copy of it.
//
// The deadline starts here, not when the ladder does: building the stages can
// fetch a target list and health-check a resolver pool, and without this the
// run would overshoot its timeout and be killed before delivering its report.
func (a *App) Run(ctx context.Context, runCfg *config.Config) (*report.Report, error) {
	started := time.Now()
	setupCtx, cancel := context.WithDeadline(ctx, pipeline.Deadline(runCfg, started))
	defer cancel()

	stages, err := a.buildStages(setupCtx, runCfg)
	if err != nil {
		return nil, err
	}
	return pipeline.New(runCfg, stages, a.log).StartedAt(started).Run(ctx)
}

// resolveCredentials resolves API keys for all possible sources.
func (a *App) resolveCredentials() map[string]secrets.Credential {
	resolver, err := secrets.NewResolver(a.cfg.ProviderConfig)
	if err != nil {
		// Unreadable config reported by the needy stage; runs without keys are still valid.
		a.log.Warn("provider config unusable", "error", err)
		return nil
	}

	// Clone to avoid writes to the backing array when appending.
	wanted := slices.Clone(a.cfg.Sources)
	if a.cfg.AllSources {
		for _, s := range enumerate.Available() {
			wanted = append(wanted, s.Name)
		}
		slices.Sort(wanted)
		wanted = slices.Compact(wanted)
	}

	creds := resolver.Resolve(wanted)
	// Inventory against all queried sources; --all-sources differs from the five defaults.
	inv := secrets.Take(wanted, creds)
	for source, origin := range inv.Configured {
		a.log.Debug("source credential", "source", source, "origin", origin)
	}
	a.log.Info("credentials resolved", "configured", len(inv.Configured), "missing", inv.Missing)
	return creds
}

// buildStages wires the stage implementations the scope calls for.
//
// Every option is read from cfg (the process configuration, or a per-request
// copy in serve mode), never a.cfg, which would silently ignore the override
// once an option becomes caller-settable. The two cached engines below take no
// run-scoped option at all.
func (a *App) buildStages(ctx context.Context, cfg *config.Config) (pipeline.Stages, error) {
	enumerator, err := a.stageOne(ctx, cfg)
	if err != nil {
		return pipeline.Stages{}, err
	}
	return a.rest(ctx, cfg, enumerator)
}

// stageOne is either enumeration or a supplied list. A list replaces the
// stage rather than skipping it, so exclusions still run on its output.
func (a *App) stageOne(ctx context.Context, cfg *config.Config) (pipeline.Enumerator, error) {
	if !cfg.HasTargets() {
		return enumerate.NewSubfaster(enumerate.Options{
			Sources:        cfg.Sources,
			ExcludeSources: cfg.ExcludeSources,
			All:            cfg.AllSources,
			SourceTimeout:  cfg.SourceTimeout,
			Credentials:    a.creds,
			Redactor:       a.redactor,
			Logger:         a.log,
		})
	}

	hosts, err := enumerate.LoadTargets(ctx, enumerate.TargetOptions{
		Inline:   cfg.Targets,
		File:     cfg.TargetsFile,
		URL:      cfg.TargetsURL,
		Headers:  cfg.TargetsHeader,
		Redactor: a.redactor,
		Logger:   a.log,
	})
	if err != nil {
		// A network-fetched list can fail for reasons unrelated to configuration.
		if cfg.TargetsURL != "" {
			return nil, fmt.Errorf("%w: %w", ErrRuntime, err)
		}
		return nil, err
	}
	return enumerate.NewList(hosts, a.log)
}

// rest wires exclusion and everything the scope reaches beyond it.
func (a *App) rest(ctx context.Context, cfg *config.Config, enumerator pipeline.Enumerator) (pipeline.Stages, error) {
	excluder, err := exclude.New(cfg.Exclude, cfg.ExcludeStrictWildcard)
	if err != nil {
		return pipeline.Stages{}, fmt.Errorf("invalid exclusions:\n%w", err)
	}

	stages := pipeline.Stages{Enumerator: enumerator, Excluder: excluder}

	// Lazy construction; enumeration-only runs skip unnecessary sockets.
	if cfg.Scope.Includes(stage.Resolve) {
		resolvers, warnings, degraded, err := a.resolverPool(ctx)
		if err != nil {
			return pipeline.Stages{}, err
		}
		cfg.Warnings = append(cfg.Warnings, warnings...)
		cfg.Degraded = append(cfg.Degraded, degraded...)

		resolver, err := resolve.New(resolve.Options{
			Domain:         cfg.Domain,
			Resolvers:      resolvers,
			Concurrency:    cfg.ResolverConcurrency,
			Retries:        cfg.ResolverRetries,
			Timeout:        cfg.ResolverTimeout,
			WildcardProbes: cfg.WildcardProbes,
			Logger:         a.log,
		})
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.Resolver = resolver
	}

	if cfg.Scope.Includes(stage.PortScan) {
		scanner, err := portscan.New(portscan.Options{
			Mode:         cfg.ScanMode,
			Ports:        cfg.Ports,
			ExcludePorts: cfg.ExcludePorts,
			SkipCDN:      cfg.SkipCDN,
			Concurrency:  cfg.ScanConcurrency,
			Rate:         cfg.ScanRate,
			Retries:      cfg.ScanRetries,
			Timeout:      cfg.ScanTimeout,
			CDN:          a.cdnRanges(),
			Logger:       a.log,
		})
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.PortScanner = scanner
	}

	if cfg.Scope.Includes(stage.HTTPProbe) {
		prober, err := a.httpProber()
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.Prober = prober
	}

	return stages, nil
}

// cdnRanges returns the shared CDN address ranges, loading them on first use.
//
// The dataset is embedded and takes no option, so one instance serves every
// run; it is built only when a scope reaches the port scan.
func (a *App) cdnRanges() *cdncheck.Client {
	a.engineMu.Lock()
	defer a.engineMu.Unlock()

	if a.cdn == nil {
		a.cdn = cdncheck.New()
		a.log.Debug("cdn ranges loaded")
	}
	return a.cdn
}

// httpProber returns the shared prober, building it on first use.
//
// Every probe option is process-level (a request chooses what to scan, never
// how the deployment probes), so one prober is built from the process
// configuration and reused. It holds the technology fingerprints and HTTP
// clients, and the httpx client has no Close, so a per-run instance would leak
// its connection pool. Reuse is safe: Probe builds its own rate limiter and
// result set on each call.
func (a *App) httpProber() (*probe.HTTPX, error) {
	a.engineMu.Lock()
	defer a.engineMu.Unlock()

	if a.prober != nil {
		return a.prober, nil
	}
	prober, err := probe.New(probe.Options{
		Concurrency:     a.cfg.ProbeConcurrency,
		Rate:            a.cfg.ProbeRate,
		Timeout:         a.cfg.ProbeTimeout,
		Retries:         a.cfg.ProbeRetries,
		FollowRedirects: a.cfg.ProbeFollowRedirects,
		MaxRedirects:    a.cfg.ProbeMaxRedirects,
		UserAgent:       a.cfg.ProbeUserAgent,
		Headers:         a.cfg.ProbeHeaders,
		SPKI:            a.cfg.ProbeSPKI,
		Logger:          a.log,
	})
	if err != nil {
		return nil, err
	}
	a.prober = prober
	a.log.Debug("technology fingerprints loaded")
	return prober, nil
}

// resolverPool loads resolver list once, health-checks and caches it.
func (a *App) resolverPool(ctx context.Context) (resolvers, warnings, degraded []string, err error) {
	a.poolMu.Lock()
	defer a.poolMu.Unlock()

	if a.pool != nil {
		return a.pool, a.poolWarnings, a.poolDegraded, nil
	}

	resolvers, err = resolve.LoadResolvers(ctx, resolve.LoadOptions{
		Inline: a.cfg.Resolvers,
		File:   a.cfg.ResolversFile,
		URL:    a.cfg.ResolversURL,
		Logger: a.log,
	})
	if err != nil {
		// Network fetch failures are transient (not configuration errors).
		if a.cfg.ResolversURL != "" {
			return nil, nil, nil, fmt.Errorf("%w: %w", ErrRuntime, err)
		}
		return nil, nil, nil, err
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
			// All resolvers failing is far more often a local condition (no
			// port 53 egress, captive network, blocked anchor) than a hostile
			// pool. Refusing would yield no report, so continue on the
			// unvalidated pool and say so in the report and the log.
			a.log.Error("resolver health check dropped every resolver; continuing without validation", "resolvers", len(resolvers))
			warnings = append(warnings, fmt.Sprintf("all %d resolvers failed the health check and the run continued without validating them: the live/dead split may be wrong", len(resolvers)))
			degraded = append(degraded, report.DegradedResolversUnvalidated)
		} else {
			// These reach the report, not just the log: results from a pool
			// that lost half its members deserve qualifying.
			if len(health.Dropped) > 0 {
				warnings = append(warnings, fmt.Sprintf("%d of %d resolvers dropped by the health check", len(health.Dropped), len(resolvers)))
			}
			if health.Unchecked > 0 {
				warnings = append(warnings, fmt.Sprintf("%d of %d resolvers were kept unchecked: the health budget ran out", health.Unchecked, len(resolvers)))
				degraded = append(degraded, report.DegradedResolversUnvalidated)
			}
			resolvers = health.Good
		}
	}

	// A check cut short by the caller (canceled, out of time) says nothing
	// about the pool: use what we got, but don't cache an unvalidated pool
	// flagged as degraded for later runs.
	if ctx.Err() != nil {
		return resolvers, warnings, degraded, nil
	}
	a.pool, a.poolWarnings, a.poolDegraded = resolvers, warnings, degraded
	return resolvers, warnings, degraded, nil
}
