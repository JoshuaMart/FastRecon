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

	// Engine cache. Two of the stage engines carry a large embedded dataset —
	// the CDN address ranges and the technology fingerprints — and building
	// them costs ~130ms and ~110MB of retained heap. Every option they take
	// is process-level, never per-request, so they are built once and shared.
	// Rebuilding them per run made a function instance pay that on every
	// request, which is how a 256MB instance runs out of memory.
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
func (a *App) Run(ctx context.Context, runCfg *config.Config) (*report.Report, error) {
	stages, err := a.buildStages(ctx, runCfg)
	if err != nil {
		return nil, err
	}
	return pipeline.New(runCfg, stages, a.log).Run(ctx)
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
// Every option is read from cfg, which is the process configuration for a CLI
// run and a per-request copy of it in serve mode. Reading one from a.cfg
// instead would work today and silently ignore the override the day that
// option becomes caller-settable, so the rule is uniform and has no
// exceptions. The two cached engines below are the deliberate counterpart:
// they take no run-scoped option at all.
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
		// A list fetched over the network can fail for reasons unrelated to
		// the configuration being wrong.
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
// run. It is only built when a scope actually reaches the port scan, which is
// what keeps an enumeration-only run from paying for it.
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
// Every probe option is process-level — a request may choose what to scan,
// never how the deployment probes — so the prober is built from the process
// configuration and reused. That reuse is the point: it holds the technology
// fingerprints and the HTTP clients, and the httpx client has no Close, so a
// per-run instance leaves its connection pool behind for the garbage
// collector to find.
//
// Reuse is safe because a prober carries no per-run state: Probe builds its
// own rate limiter and result set on each call.
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
			// Every resolver failing is far more often a local condition — no
			// egress on port 53, a captive network, a blocked anchor — than a
			// pool that is genuinely all hostile. Refusing to run turns that
			// into no report at all, so the run continues on the unvalidated
			// pool and says so, in the report as well as the log.
			a.log.Error("resolver health check dropped every resolver; continuing without validation", "resolvers", len(resolvers))
			warnings = append(warnings, fmt.Sprintf("all %d resolvers failed the health check and the run continued without validating them: the live/dead split may be wrong", len(resolvers)))
			degraded = append(degraded, report.DegradedResolversUnvalidated)
		} else {
			// These reach the report, not just the log: a resolution done
			// through a pool that lost half its members is a result worth
			// qualifying.
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

	a.pool, a.poolWarnings, a.poolDegraded = resolvers, warnings, degraded
	return resolvers, warnings, degraded, nil
}
