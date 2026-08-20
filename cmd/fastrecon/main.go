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
	"syscall"

	"github.com/spf13/pflag"

	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/enumerate"
	"github.com/JoshuaMart/FastRecon/internal/exclude"
	"github.com/JoshuaMart/FastRecon/internal/logging"
	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
	"github.com/JoshuaMart/FastRecon/internal/sink"
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

	// The webhook sink lands with the hardening phase. Accepting the flag and
	// quietly not delivering would look like a successful run to whatever is
	// waiting for the POST, so refuse it outright.
	if cfg.WebhookURL != "" {
		fmt.Fprintln(os.Stderr, "fastrecon: --webhook-url is not part of this build yet (see SPECIFICATIONS.md, phase 6); use --output for now")
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
	// reaches its destinations.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stages, err := buildStages(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
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

	sinks := buildSinks(cfg)
	results := sink.DeliverAll(ctx, data, sinks)
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
func buildStages(cfg *config.Config, log *slog.Logger) (pipeline.Stages, error) {
	resolver, err := secrets.NewResolver(cfg.ProviderConfig)
	if err != nil {
		return pipeline.Stages{}, err
	}

	wanted := cfg.Sources
	if cfg.AllSources {
		for _, s := range enumerate.Available() {
			wanted = append(wanted, s.Name)
		}
	}
	creds := resolver.Resolve(wanted)
	logCredentials(log, cfg.Sources, creds)

	enumerator, err := enumerate.NewSubfaster(enumerate.Options{
		Sources:        cfg.Sources,
		ExcludeSources: cfg.ExcludeSources,
		All:            cfg.AllSources,
		SourceTimeout:  cfg.SourceTimeout,
		Credentials:    creds,
		Redactor:       secrets.NewRedactor(creds),
		Logger:         log,
	})
	if err != nil {
		return pipeline.Stages{}, err
	}

	excluder, err := exclude.New(cfg.Exclude, cfg.ExcludeStrictWildcard)
	if err != nil {
		return pipeline.Stages{}, fmt.Errorf("invalid exclusions:\n%w", err)
	}

	return pipeline.Stages{Enumerator: enumerator, Excluder: excluder}, nil
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

func buildSinks(cfg *config.Config) []sink.Sink {
	stdout, file, _ := cfg.Sinks()
	var sinks []sink.Sink
	if stdout {
		sinks = append(sinks, sink.NewStdout())
	}
	if file {
		sinks = append(sinks, sink.NewFile(cfg.Output))
	}
	return sinks
}
