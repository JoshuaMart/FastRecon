// Package pipeline orchestrates the recon stages.
//
// The pipeline owns the ladder, the deadline budgeting and the report; the
// stages themselves are interfaces, so each one can be built, replaced or
// tested without touching the orchestration.
package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/runid"
	"github.com/JoshuaMart/FastRecon/internal/stage"
	"github.com/JoshuaMart/FastRecon/internal/version"
)

// Partial is embedded by every stage result. A stage can finish without
// having been exhaustive — a source timed out, half the hosts were resolved
// before the budget ran out — and that has to reach the report, because a
// truncated result that claims to be complete is worse than no result.
type Partial struct {
	// Warnings are non-fatal problems worth putting in the report.
	Warnings []string
	// Truncated marks a stage cut short by its deadline.
	Truncated bool
}

// Enumeration is what an Enumerator produces: the hosts it found, plus the
// per-source accounting that makes a silently empty source visible.
type Enumeration struct {
	Partial
	Hosts   []string
	Sources []report.Source
}

// Resolution is what a Resolver produces: every host it was given, each with
// its verdict. Dead hosts are kept — a dangling CNAME is a finding, not noise.
type Resolution struct {
	Partial
	Hosts []report.Host
}

// Filtered is the outcome of applying the exclusion patterns.
type Filtered struct {
	Kept    []string
	Removed []report.Excluded
	// Unused lists patterns that matched nothing — almost always a typo.
	Unused []string
}

// Enumerator collects subdomains from passive sources.
type Enumerator interface {
	Name() string
	Enumerate(ctx context.Context, domain string) (Enumeration, error)
}

// Excluder drops out-of-scope hosts before any network activity happens.
type Excluder interface {
	Name() string
	Filter(hosts []string) Filtered
}

// Resolver splits hosts into live and dead.
type Resolver interface {
	Name() string
	Resolve(ctx context.Context, hosts []string) (Resolution, error)
}

// PortScan is what a PortScanner produces: every host it was given, the live
// ones enriched with their open ports and the CDN determination.
type PortScan struct {
	Partial
	Hosts []report.Host
}

// PortScanner enriches live hosts with their open ports.
type PortScanner interface {
	Name() string
	Scan(ctx context.Context, hosts []report.Host) (PortScan, error)
}

// Probe is what a Prober produces: the hosts, with the open ports that
// answered HTTP carrying their service details.
type Probe struct {
	Partial
	Hosts []report.Host
}

// Prober enriches open ports with the HTTP service behind them.
type Prober interface {
	Name() string
	Probe(ctx context.Context, hosts []report.Host) (Probe, error)
}

// Stages holds the implementations wired into a run. A nil field means the
// stage is not available in this build: the run stops there and says so,
// rather than reporting an empty result as if it were a finding.
type Stages struct {
	Enumerator  Enumerator
	Excluder    Excluder
	Resolver    Resolver
	PortScanner PortScanner
	Prober      Prober
}

// Pipeline runs one recon job.
type Pipeline struct {
	cfg    *config.Config
	stages Stages
	log    *slog.Logger
	now    func() time.Time
}

// New builds a pipeline.
func New(cfg *config.Config, stages Stages, log *slog.Logger) *Pipeline {
	return &Pipeline{cfg: cfg, stages: stages, log: log, now: time.Now}
}

// ErrNoImplementation is returned by a stage that is not part of this build.
var ErrNoImplementation = errors.New("stage not implemented in this build")

// Run executes the scope's stages and always returns a report.
//
// A stage failure or an expired deadline stops the ladder — every later stage
// consumes the previous one's output — but the report produced so far is
// still returned, marked incomplete. A run that ran out of time is data, not
// an error.
func (p *Pipeline) Run(ctx context.Context) (*report.Report, error) {
	started := p.now()
	cfg := p.cfg

	rep := report.New(
		runid.New(started),
		cfg.Domain,
		cfg.Scope,
		version.Version,
		config.DetectEnvironment(cfg.Environment, false),
		started,
	)
	for _, w := range cfg.Warnings {
		rep.Warnf("%s", w)
	}

	// Reserve a slice of the deadline to build and deliver the report, so a
	// tight budget yields a truncated report instead of a killed process.
	usable := time.Duration(float64(cfg.Timeout) * (1 - cfg.OutputMargin))
	budget := NewBudget(cfg.Scope.Stages(), started.Add(usable))
	budget.now = p.now

	p.log.Info("run started",
		"run_id", rep.Run.ID,
		"domain", cfg.Domain,
		"scope", cfg.Scope.String(),
		"stages", cfg.Scope.StageNames(),
		"deadline", budget.Deadline().UTC().Format(time.RFC3339),
	)

	state := &runState{report: rep}
	for _, st := range cfg.Scope.Stages() {
		if err := ctx.Err(); err != nil {
			p.stop(rep, st, err)
			break
		}
		if budget.Expired() {
			p.stop(rep, st, context.DeadlineExceeded)
			break
		}
		if err := p.runStage(ctx, st, budget, state); err != nil {
			p.stop(rep, st, err)
			break
		}
	}

	rep.Finish(p.now())
	p.logSummary(rep)
	return rep, nil
}

// runState carries values between stages.
type runState struct {
	report *report.Report
	hosts  []string
	found  []report.Host
}

func (p *Pipeline) runStage(ctx context.Context, st stage.Stage, budget *Budget, state *runState) error {
	allotted := budget.Take(st)
	if allotted <= 0 {
		return context.DeadlineExceeded
	}
	stageCtx, cancel := context.WithTimeout(ctx, allotted)
	defer cancel()

	start := p.now()
	p.log.Debug("stage started", "stage", string(st), "budget", allotted.String())

	err := p.dispatch(stageCtx, st, state)
	if err != nil {
		return err
	}

	p.log.Info("stage finished",
		"stage", string(st),
		"duration_ms", p.now().Sub(start).Milliseconds(),
		"hosts", len(state.hosts),
	)
	return nil
}

func (p *Pipeline) dispatch(ctx context.Context, st stage.Stage, state *runState) error {
	rep := state.report
	switch st {
	case stage.Enumerate:
		if p.stages.Enumerator == nil {
			return ErrNoImplementation
		}
		res, err := p.stages.Enumerator.Enumerate(ctx, p.cfg.Domain)
		if err != nil {
			return err
		}
		state.hosts = res.Hosts
		rep.Sources = res.Sources
		rep.Stats.Enumerated = len(res.Hosts)
		p.applyPartial(ctx, rep, st, res.Partial)
		return nil

	case stage.Exclude:
		if p.stages.Excluder == nil {
			return ErrNoImplementation
		}
		res := p.stages.Excluder.Filter(state.hosts)
		state.hosts = res.Kept
		rep.Stats.Excluded = len(res.Removed)
		rep.Stats.InScope = len(res.Kept)
		// Publish the surviving hosts now, so an enumeration-only run
		// reports the subdomains it found rather than just counting them.
		// The resolve stage replaces these with their live/dead verdict.
		rep.Hosts = make([]report.Host, 0, len(res.Kept))
		for _, h := range res.Kept {
			rep.Hosts = append(rep.Hosts, report.Host{Host: h, Status: report.StatusDiscovered})
		}
		if p.cfg.ReportExcluded {
			rep.Excluded = res.Removed
		}
		for _, pattern := range res.Unused {
			rep.Warnf("exclusion pattern %q matched nothing", pattern)
		}
		return nil

	case stage.Resolve:
		if p.stages.Resolver == nil {
			return ErrNoImplementation
		}
		res, err := p.stages.Resolver.Resolve(ctx, state.hosts)
		if err != nil {
			return err
		}
		state.found = res.Hosts
		rep.Hosts = res.Hosts
		p.applyPartial(ctx, rep, st, res.Partial)
		return nil

	case stage.PortScan:
		if p.stages.PortScanner == nil {
			return ErrNoImplementation
		}
		res, err := p.stages.PortScanner.Scan(ctx, state.found)
		if err != nil {
			return err
		}
		state.found = res.Hosts
		rep.Hosts = res.Hosts
		p.applyPartial(ctx, rep, st, res.Partial)
		return nil

	case stage.HTTPProbe:
		if p.stages.Prober == nil {
			return ErrNoImplementation
		}
		res, err := p.stages.Prober.Probe(ctx, state.found)
		if err != nil {
			return err
		}
		state.found = res.Hosts
		rep.Hosts = res.Hosts
		p.applyPartial(ctx, rep, st, res.Partial)
		return nil

	default:
		return errors.New("unknown stage " + string(st))
	}
}

// applyPartial folds a stage's non-fatal outcome into the report. A truncated
// stage does not stop the ladder — the later stages still have their own
// budget and can work on what was found — but the run stops claiming to be
// complete.
//
// A deadline and an operator stopping the job both cut a stage short, and
// they are reported differently: a consumer may reasonably retry a run that
// ran out of time, and must not retry one somebody stopped on purpose.
func (p *Pipeline) applyPartial(ctx context.Context, rep *report.Report, st stage.Stage, part Partial) {
	for _, w := range part.Warnings {
		rep.Warnf("%s", w)
	}
	if !part.Truncated {
		return
	}
	rep.Run.Completed = false

	if errors.Is(ctx.Err(), context.Canceled) {
		rep.Warnf("stage %s: run canceled, results are partial", st)
		p.log.Warn("stage canceled", "stage", string(st))
		return
	}
	rep.Run.TruncatedByTimeout = true
	rep.Warnf("stage %s: cut short by its deadline, results are partial", st)
	p.log.Warn("stage truncated", "stage", string(st))
}

// stop records why the ladder ended early. The report stays valid; only its
// completeness flags change.
func (p *Pipeline) stop(rep *report.Report, st stage.Stage, err error) {
	rep.Run.Completed = false
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		rep.Run.TruncatedByTimeout = true
		rep.Warnf("stage %s: run deadline reached, results are partial", st)
		p.log.Warn("run truncated by timeout", "stage", string(st))
	case errors.Is(err, context.Canceled):
		rep.Warnf("stage %s: run canceled, results are partial", st)
		p.log.Warn("run canceled", "stage", string(st))
	case errors.Is(err, ErrNoImplementation):
		rep.Warnf("stage %s: %s", st, ErrNoImplementation)
		p.log.Warn("stage unavailable", "stage", string(st), "error", err)
	default:
		rep.Warnf("stage %s failed: %s", st, err)
		p.log.Error("stage failed", "stage", string(st), "error", err)
	}
}

// logSummary emits the run counters to stderr. In a log-only environment the
// report itself may go to a webhook, so the outcome has to be legible here.
func (p *Pipeline) logSummary(rep *report.Report) {
	p.log.Info("run finished",
		"run_id", rep.Run.ID,
		"domain", rep.Run.Domain,
		"completed", rep.Run.Completed,
		"truncated_by_timeout", rep.Run.TruncatedByTimeout,
		"duration_ms", rep.Run.Duration,
		"enumerated", rep.Stats.Enumerated,
		"excluded", rep.Stats.Excluded,
		"in_scope", rep.Stats.InScope,
		"live", rep.Stats.Live,
		"dead", rep.Stats.Dead,
		"wildcard", rep.Stats.Wildcard,
		"open_ports", rep.Stats.OpenPorts,
		"http_services", rep.Stats.HTTPServices,
		"warnings", len(rep.Warnings),
	)
}
