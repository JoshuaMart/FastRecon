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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/JoshuaMart/FastRecon/internal/app"
	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/enumerate"
	"github.com/JoshuaMart/FastRecon/internal/logging"
	"github.com/JoshuaMart/FastRecon/internal/serve"
	"github.com/JoshuaMart/FastRecon/internal/sink"
	"github.com/JoshuaMart/FastRecon/internal/version"
)

// Exit codes (distinct statuses for job schedulers).
const (
	exitOK         = 0 // run completed, report emitted
	exitUsage      = 1 // invalid configuration
	exitIncomplete = 2 // run did not finish its scope
	exitSinkFailed = 3 // delivery failed
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
			return serveMode(args[1:])
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

// serveMode answers run requests over HTTP, for the function deployment.
func serveMode(args []string) int {
	fs := newFlagSet()
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}

	// The domain is not known at startup here: it arrives with each request.
	cfg, err := config.LoadServe(fs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: invalid configuration:\n%v\n", err)
		return exitUsage
	}
	// Explicitly labeled; nothing distinguishes a function from other containers.
	if cfg.Environment == "" {
		cfg.Environment = config.EnvServerlessFunction
	}

	log, err := logging.New(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}
	for _, w := range cfg.Warnings {
		log.Warn("configuration", "warning", w)
	}

	application, err := app.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}
	server, err := serve.New(application, cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.ListenAndServe(ctx, cfg.Listen); err != nil {
		log.Error("serve failed", "error", err)
		return exitFatal
	}
	return exitOK
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

	// Cancel run on signal so partial reports reach their destinations; created early so resolver loading is cancellable.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := app.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}

	rep, err := application.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		// A scheduler keys its retry on the exit status. Reporting a network
		// blip as a configuration error means it never retries something that
		// would have worked on the next run.
		if errors.Is(err, app.ErrRuntime) {
			return exitFatal
		}
		// Everything else that stops a run before it starts is a mistake in
		// the configuration: an unparseable exclusion, an impossible scan
		// mode, a port list that is not one.
		return exitUsage
	}

	data, err := rep.Render(cfg.Format)
	if err != nil {
		log.Error("render report", "error", err)
		return exitFatal
	}
	data = application.Redactor().RedactBytes(data)

	sinks, err := buildSinks(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fastrecon: %v\n", err)
		return exitUsage
	}

	// Delivery on detached context; partial reports reach destinations despite signal.
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

// deliveryContext allocates budget for report delivery.
func deliveryContext(cfg *config.Config) (context.Context, context.CancelFunc) {
	budget := time.Duration(float64(cfg.Timeout) * cfg.OutputMargin)
	if budget <= 0 {
		budget = 30 * time.Second
	}
	return context.WithTimeout(context.WithoutCancel(context.Background()), budget)
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
		// Log header names only (values contain bearer tokens).
		log.Debug("webhook configured", "url", cfg.WebhookURL, "method", cfg.WebhookMethod, "headers", headerNames(cfg.WebhookHeaders))
	}
	return sinks, nil
}

// headerNames extracts header names (omits values).
func headerNames(headers []string) []string {
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		name, _, _ := strings.Cut(h, ":")
		out = append(out, strings.TrimSpace(name))
	}
	return out
}
