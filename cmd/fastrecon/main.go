// Command fastrecon discovers the attack surface of a domain.
//
// The same binary serves every deployment: a local CLI run, a container, a
// serverless job, and — from the `serve` subcommand — a serverless function.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/enumerate"
	"github.com/JoshuaMart/FastRecon/internal/exclude"
	"github.com/JoshuaMart/FastRecon/internal/logging"
	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/portscan"
	"github.com/JoshuaMart/FastRecon/internal/probe"
	"github.com/JoshuaMart/FastRecon/internal/resolve"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
	"github.com/JoshuaMart/FastRecon/internal/sink"
	"github.com/JoshuaMart/FastRecon/internal/stage"
	"github.com/JoshuaMart/FastRecon/internal/version"
)

// Exit codes. A job scheduler's only signal is the exit status, so an
// incomplete run, a failed delivery and a fatal error must not look alike.
const (
	exitOK         = 0 // run completed, report emitted
	exitUsage      = 1 // invalid configuration or usage
	exitIncomplete = 2 // report emitted, but the run did not finish its scope
	exitSinkFailed = 3 // report produced, at least one destination failed
	exitFatal      = 4 // no report produced
)

func main() {
	os.Exit(dispatch(os.Args[1:]))
}

func dispatch(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Println("fastrecon", version.String())
			return exitOK
		case "serve":
			fmt.Fprintln(os.Stderr, "fastrecon: serve mode is not part of this build yet (see SPECIFICATIONS.md, phase 8)")
			return exitUsage
		case "run":
			args = args[1:]
		case "sources":
			listSources()
			return exitOK
		case "help":
			usage(newFlagSet())
			return exitOK
		}
	}
	return run(args)
}

func newFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("fastrecon", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.Usage = func() { usage(fs) }
	config.RegisterFlags(fs)
	return fs
}

func usage(fs *pflag.FlagSet) {
	fmt.Fprintf(os.Stderr, `fastrecon %s — attack-surface discovery

Usage:
  fastrecon [run] -d <domain> [options]
  fastrecon serve [options]
  fastrecon sources
  fastrecon version

Every option below is also settable as an environment variable (--http-timeout
becomes FASTRECON_HTTP_TIMEOUT) or as a config-file key of the same name.
Precedence: flag > environment > config file > default.

Options:
%s`, version.Version, fs.FlagUsages())
}

func run(args []string) int {
	fs := newFlagSet()
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}
	if extra := fs.Args(); len(extra) > 0 {
		fmt.Fprintf(os.Stderr, "fastrecon: unexpected argument %q\n", extra[0])
		return exitUsage
	}

	cfg, err := config.Load(fs)
	if err != nil {
		// Configuration errors are reported all at once, one per line.
		fmt.Fprintf(os.Stderr, "fastrecon: invalid configuration:\n%v\n", err)
		return exitUsage
	}

	log, err := logging.New(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}
	for _, w := range cfg.Warnings {
		log.Warn("configuration", "warning", w)
	}
	if cfg.ConfigFile != "" {
		log.Debug("config file loaded", "path", cfg.ConfigFile)
	}

	// A stopped job or a container shutdown arrives as a signal. Cancelling
	// the run rather than dying on the spot means the partial report still
	// reaches its destinations. It is created before the stages are built so
	// that resolver loading and health checking are cancellable too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	creds := resolveCredentials(cfg, log)
	redactor := secrets.NewRedactor(creds)

	stages, err := buildStages(ctx, cfg, log, creds, redactor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		// A scheduler keys its retry on the exit status. Reporting a network
		// blip as a configuration error means it never retries something that
		// would have worked on the next run.
		if errors.Is(err, errRuntime) {
			return exitFatal
		}
		return exitUsage
	}

	rep, err := pipeline.New(cfg, stages, log).Run(ctx)
	if err != nil {
		log.Error("run failed", "error", err)
		return exitFatal
	}

	data, err := rep.Render(cfg.Format)
	if err != nil {
		log.Error("render report", "error", err)
		return exitFatal
	}
	data = redactor.RedactBytes(data)

	sinks, err := buildSinks(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}

	// Delivery runs on its own context, detached from the run's. A stopped
	// job arrives as a signal that cancels ctx, and the whole point of
	// catching it is that the partial report still reaches its destinations —
	// which a cancelled context would prevent.
	deliverCtx, cancelDelivery := deliveryContext(cfg)
	defer cancelDelivery()

	results := sink.DeliverAll(deliverCtx, data, sinks)
	for _, r := range results {
		if r.Err != nil {
			log.Error("delivery failed", "sink", r.Sink, "error", r.Err)
			continue
		}
		log.Info("report delivered", "sink", r.Sink)
	}

	switch {
	case sink.Errs(results) != nil:
		return exitSinkFailed
	case !rep.Run.Completed:
		return exitIncomplete
	default:
		return exitOK
	}
}

// buildStages wires the stage implementations available in this build. The
// stages beyond exclusion land in later phases; the pipeline reports the
// ladder stopping rather than inventing an empty result.
// errRuntime marks a preparation failure that is transient rather than a
// mistake in the configuration: an unreachable resolver list, a health check
// that found nothing usable. It selects the exit code, which is the only
// signal a job scheduler has.
var errRuntime = errors.New("runtime failure")

// deliveryContext bounds the report delivery, using the slice of the run
// budget that was reserved for exactly this.
func deliveryContext(cfg *config.Config) (context.Context, context.CancelFunc) {
	budget := time.Duration(float64(cfg.Timeout) * cfg.OutputMargin)
	if budget <= 0 {
		budget = 30 * time.Second
	}
	return context.WithTimeout(context.WithoutCancel(context.Background()), budget)
}

// resolveCredentials resolves the source keys once, up front. The values are
// process-global from here on, so they are settled before any stage exists.
func resolveCredentials(cfg *config.Config, log *slog.Logger) map[string]secrets.Credential {
	resolver, err := secrets.NewResolver(cfg.ProviderConfig)
	if err != nil {
		// A provider config that cannot be read is reported by the stage that
		// needs it; a run without keys is still a run.
		log.Warn("provider config unusable", "error", err)
		return nil
	}

	// Cloned: appending to cfg.Sources would write into its backing array
	// whenever it has spare capacity.
	wanted := slices.Clone(cfg.Sources)
	if cfg.AllSources {
		for _, s := range enumerate.Available() {
			wanted = append(wanted, s.Name)
		}
		slices.Sort(wanted)
		wanted = slices.Compact(wanted)
	}
	creds := resolver.Resolve(wanted)
	// Reported against every source that will be queried, not just the
	// default five: under --all-sources the two differ completely.
	logCredentials(log, wanted, creds)
	return creds
}

func buildStages(ctx context.Context, cfg *config.Config, log *slog.Logger, creds map[string]secrets.Credential, redactor *secrets.Redactor) (pipeline.Stages, error) {
	enumerator, err := enumerate.NewSubfaster(enumerate.Options{
		Sources:        cfg.Sources,
		ExcludeSources: cfg.ExcludeSources,
		All:            cfg.AllSources,
		SourceTimeout:  cfg.SourceTimeout,
		Credentials:    creds,
		Redactor:       redactor,
		Logger:         log,
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
		resolvers, err := buildResolverPool(ctx, cfg, log)
		if err != nil {
			return pipeline.Stages{}, err
		}
		resolver, err := resolve.New(resolve.Options{
			Domain:         cfg.Domain,
			Resolvers:      resolvers,
			Concurrency:    cfg.ResolverConcurrency,
			Retries:        cfg.ResolverRetries,
			Timeout:        cfg.ResolverTimeout,
			WildcardProbes: cfg.WildcardProbes,
			Logger:         log,
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
			Logger:       log,
		})
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.PortScanner = scanner
	}

	if cfg.Scope.Includes(stage.HTTPProbe) {
		prober, err := probe.New(probe.Options{
			Concurrency:     cfg.ProbeConcurrency,
			Rate:            cfg.ProbeRate,
			Timeout:         cfg.ProbeTimeout,
			Retries:         cfg.ProbeRetries,
			FollowRedirects: cfg.ProbeFollowRedirects,
			MaxRedirects:    cfg.ProbeMaxRedirects,
			UserAgent:       cfg.ProbeUserAgent,
			Headers:         cfg.ProbeHeaders,
			Logger:          log,
		})
		if err != nil {
			return pipeline.Stages{}, err
		}
		stages.Prober = prober
	}

	return stages, nil
}

// buildResolverPool assembles the resolver list and, unless told otherwise,
// removes the resolvers that cannot be trusted to answer correctly.
func buildResolverPool(ctx context.Context, cfg *config.Config, log *slog.Logger) ([]string, error) {
	resolvers, err := resolve.LoadResolvers(ctx, resolve.LoadOptions{
		Inline: cfg.Resolvers,
		File:   cfg.ResolversFile,
		URL:    cfg.ResolversURL,
		Logger: log,
	})
	if err != nil {
		// Fetching a list over the network can fail for reasons that have
		// nothing to do with the configuration being wrong.
		if cfg.ResolversURL != "" {
			return nil, fmt.Errorf("%w: %w", errRuntime, err)
		}
		return nil, err
	}
	log.Info("resolvers loaded", "count", len(resolvers))

	if !cfg.ValidateResolvers {
		return resolvers, nil
	}

	health := resolve.CheckResolvers(ctx, resolvers, resolve.HealthOptions{
		Budget:      cfg.ResolverHealthBudget,
		Timeout:     cfg.ResolverTimeout,
		Concurrency: cfg.ResolverConcurrency,
		Logger:      log,
	})
	if len(health.Good) == 0 {
		return nil, fmt.Errorf("%w: every one of the %d configured resolvers failed the health check", errRuntime, len(resolvers))
	}
	// These reach the report, not just the log: a resolution done through a
	// pool that lost half its members is a result worth qualifying.
	if len(health.Dropped) > 0 {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%d of %d resolvers dropped by the health check", len(health.Dropped), len(resolvers)))
	}
	if health.Unchecked > 0 {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%d of %d resolvers were kept unchecked: the health budget ran out", health.Unchecked, len(resolvers)))
	}
	return health.Good, nil
}

// logCredentials reports which sources have a key and where it came from.
// Values are never logged, not even truncated.
func logCredentials(log *slog.Logger, sources []string, creds map[string]secrets.Credential) {
	inv := secrets.Take(sources, creds)
	for source, origin := range inv.Configured {
		log.Debug("source credential", "source", source, "origin", origin)
	}
	log.Info("credentials resolved",
		"configured", len(inv.Configured),
		"missing", inv.Missing,
	)
}

func listSources() {
	fmt.Printf("%-18s %-10s %s\n", "SOURCE", "KEY", "DEFAULT")
	for _, s := range enumerate.Available() {
		def := ""
		if s.Default {
			def = "yes"
		}
		fmt.Printf("%-18s %-10s %s\n", s.Name, s.Key, def)
	}
}

func buildSinks(cfg *config.Config, log *slog.Logger) ([]sink.Sink, error) {
	stdout, file, webhook := cfg.Sinks()
	var sinks []sink.Sink
	if stdout {
		sinks = append(sinks, sink.NewStdout())
	}
	if file {
		sinks = append(sinks, sink.NewFile(cfg.Output))
	}
	if webhook {
		w, err := sink.NewWebhook(sink.WebhookOptions{
			URL:     cfg.WebhookURL,
			Method:  cfg.WebhookMethod,
			Headers: cfg.WebhookHeaders,
			Timeout: cfg.WebhookTimeout,
			Retries: cfg.WebhookRetries,
			Logger:  log,
		})
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, w)
		// Header names only: a webhook header is where the bearer token goes.
		log.Debug("webhook configured", "url", cfg.WebhookURL, "method", cfg.WebhookMethod, "headers", headerNames(cfg.WebhookHeaders))
	}
	return sinks, nil
}

// headerNames lists the configured header names without their values.
func headerNames(headers []string) []string {
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		name, _, _ := strings.Cut(h, ":")
		out = append(out, strings.TrimSpace(name))
	}
	return out
}
