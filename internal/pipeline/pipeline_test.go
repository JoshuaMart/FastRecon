package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/logging"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/stage"
)

type fakeEnumerator struct {
	hosts []string
	err   error
	slow  time.Duration
}

func (f fakeEnumerator) Name() string { return "fake" }
func (f fakeEnumerator) Enumerate(ctx context.Context, _ string) (Enumeration, error) {
	if f.slow > 0 {
		select {
		case <-time.After(f.slow):
		case <-ctx.Done():
			return Enumeration{}, ctx.Err()
		}
	}
	if f.err != nil {
		return Enumeration{}, f.err
	}
	return Enumeration{
		Hosts:   f.hosts,
		Sources: []report.Source{{Name: "fake", Status: report.SourceOK, Found: len(f.hosts)}},
	}, nil
}

type fakeExcluder struct {
	drop   string
	unused []string
}

func (fakeExcluder) Name() string { return "fake" }
func (f fakeExcluder) Filter(hosts []string) Filtered {
	out := Filtered{Unused: f.unused}
	for _, h := range hosts {
		if h == f.drop {
			out.Removed = append(out.Removed, report.Excluded{Host: h, Pattern: f.drop})
			continue
		}
		out.Kept = append(out.Kept, h)
	}
	return out
}

type fakeResolver struct{ live []string }

func (fakeResolver) Name() string { return "fake" }
func (f fakeResolver) Resolve(_ context.Context, hosts []string) (Resolution, error) {
	out := make([]report.Host, 0, len(hosts))
	for _, h := range hosts {
		status, reason := report.StatusDead, report.ReasonNXDomain
		for _, l := range f.live {
			if l == h {
				status, reason = report.StatusLive, ""
				break
			}
		}
		out = append(out, report.Host{Host: h, Status: status, Reason: reason})
	}
	return Resolution{Hosts: out}, nil
}

func testConfig(t *testing.T, scope stage.Scope) *config.Config {
	t.Helper()
	return &config.Config{
		Domain:       "example.com",
		Scope:        scope,
		Timeout:      time.Minute,
		OutputMargin: 0.1,
		Output:       config.StdoutPath,
		Format:       report.FormatJSON,
	}
}

func TestRunStopsAtTheFirstMissingStage(t *testing.T) {
	cfg := testConfig(t, stage.ScopeFull)
	rep, err := New(cfg, Stages{}, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error instead of a report: %v", err)
	}
	if rep.Run.Completed {
		t.Error("a run with no stage implementation must not report itself complete")
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "enumerate") {
		t.Errorf("warnings = %v, want one naming the enumerate stage", rep.Warnings)
	}
	if rep.Run.TruncatedByTimeout {
		t.Error("a missing implementation is not a timeout")
	}
}

func TestRunEnumScopeStopsBeforeResolving(t *testing.T) {
	cfg := testConfig(t, stage.ScopeEnum)
	stages := Stages{
		Enumerator: fakeEnumerator{hosts: []string{"a.example.com", "b.example.com"}},
		Excluder:   fakeExcluder{drop: "b.example.com"},
		// A resolver is wired but must never run at this scope.
		Resolver: fakeResolver{live: []string{"a.example.com"}},
	}
	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Run.Completed {
		t.Errorf("run not completed, warnings: %v", rep.Warnings)
	}
	if rep.Stats.Enumerated != 2 || rep.Stats.Excluded != 1 || rep.Stats.InScope != 1 {
		t.Errorf("stats = %+v, want 2 enumerated / 1 excluded / 1 in scope", rep.Stats)
	}
	// An enumeration-only run must still carry the hosts it found.
	if len(rep.Hosts) != 1 || rep.Hosts[0].Host != "a.example.com" {
		t.Errorf("hosts = %v, want the surviving host listed", rep.Hosts)
	}
	if rep.Hosts[0].Status != report.StatusDiscovered {
		t.Errorf("status = %q, want %q: nothing was resolved at this scope", rep.Hosts[0].Status, report.StatusDiscovered)
	}
	if rep.Stats.Live != 0 || rep.Stats.Dead != 0 {
		t.Error("a discovered host must not count as live or dead")
	}
	if len(rep.Sources) != 1 {
		t.Errorf("sources = %v, want the source accounting to reach the report", rep.Sources)
	}
}

func TestRunResolveScopeSplitsLiveAndDead(t *testing.T) {
	cfg := testConfig(t, stage.ScopeResolve)
	stages := Stages{
		Enumerator: fakeEnumerator{hosts: []string{"a.example.com", "old.example.com"}},
		Excluder:   fakeExcluder{},
		Resolver:   fakeResolver{live: []string{"a.example.com"}},
	}
	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stats.Live != 1 || rep.Stats.Dead != 1 {
		t.Errorf("live/dead = %d/%d, want 1/1", rep.Stats.Live, rep.Stats.Dead)
	}
	// A dangling host is a finding, not noise: it stays in the report.
	if len(rep.Hosts) != 2 {
		t.Errorf("hosts = %d, want dead hosts kept in the report", len(rep.Hosts))
	}
}

func TestUnusedExclusionPatternWarns(t *testing.T) {
	cfg := testConfig(t, stage.ScopeEnum)
	stages := Stages{
		Enumerator: fakeEnumerator{hosts: []string{"a.example.com"}},
		Excluder:   fakeExcluder{unused: []string{"*.qa.example.com"}},
	}
	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "qa.example.com") {
		t.Errorf("warnings = %v, want the unused pattern surfaced", rep.Warnings)
	}
	if !rep.Run.Completed {
		t.Error("an unused pattern is a warning, not a failure")
	}
}

func TestRunReportsPartialResultsOnTimeout(t *testing.T) {
	cfg := testConfig(t, stage.ScopeFull)
	cfg.Timeout = 50 * time.Millisecond
	stages := Stages{Enumerator: fakeEnumerator{slow: time.Second}}

	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatalf("a run that ran out of time must still return a report: %v", err)
	}
	if !rep.Run.TruncatedByTimeout {
		t.Error("truncated_by_timeout not set")
	}
	if rep.Run.Completed {
		t.Error("completed must be false on a truncated run")
	}
	if rep.Run.Finished.IsZero() {
		t.Error("a truncated report must still be well formed")
	}
}

func TestRunSurfacesStageFailure(t *testing.T) {
	cfg := testConfig(t, stage.ScopeResolve)
	stages := Stages{Enumerator: fakeEnumerator{err: errors.New("all sources down")}}

	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Run.Completed || rep.Run.TruncatedByTimeout {
		t.Error("a stage failure is neither a completion nor a timeout")
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "all sources down") {
		t.Errorf("warnings = %v, want the underlying error", rep.Warnings)
	}
}

func TestRunCarriesConfigWarningsIntoTheReport(t *testing.T) {
	cfg := testConfig(t, stage.ScopeEnum)
	cfg.Warnings = []string{`config file key "porst" matches no option and was ignored`}
	stages := Stages{Enumerator: fakeEnumerator{}, Excluder: fakeExcluder{}}

	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "porst") {
		t.Errorf("warnings = %v, want the configuration warning carried through", rep.Warnings)
	}
}

// A stage that finished but was cut short must not leave the run claiming to
// be complete.
func TestTruncatedStageMarksTheRunIncomplete(t *testing.T) {
	cfg := testConfig(t, stage.ScopeEnum)
	stages := Stages{
		Enumerator: truncatingEnumerator{},
		Excluder:   fakeExcluder{},
	}
	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Run.Completed {
		t.Error("a truncated stage must clear completed")
	}
	if !rep.Run.TruncatedByTimeout {
		t.Error("truncated_by_timeout not set")
	}
	// The hosts it did find must survive.
	if len(rep.Hosts) != 1 {
		t.Errorf("hosts = %v, want the partial result kept", rep.Hosts)
	}
	if len(rep.Warnings) == 0 {
		t.Error("a truncated stage must leave a warning in the report")
	}
}

type truncatingEnumerator struct{}

func (truncatingEnumerator) Name() string { return "truncating" }
func (truncatingEnumerator) Enumerate(context.Context, string) (Enumeration, error) {
	e := Enumeration{Hosts: []string{"a.example.com"}}
	e.Truncated = true
	e.Warnings = []string{"source crt: deadline reached"}
	return e, nil
}

func TestRunCanceledByContext(t *testing.T) {
	cfg := testConfig(t, stage.ScopeFull)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rep, err := New(cfg, Stages{Enumerator: fakeEnumerator{}}, logging.Discard()).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Run.Completed {
		t.Error("a canceled run must be marked incomplete")
	}
	if rep.Run.TruncatedByTimeout {
		t.Error("cancellation is not a timeout")
	}
}

// The resolve stage rebuilds the host list from scratch, so attribution
// attached at stage 1 has to be re-applied or it silently disappears on any
// scope past enum.
func TestSourceAttributionSurvivesResolution(t *testing.T) {
	cfg := testConfig(t, stage.ScopeResolve)
	stages := Stages{
		Enumerator: attributingEnumerator{},
		Excluder:   fakeExcluder{},
		Resolver:   fakeResolver{live: []string{"a.example.com"}},
	}

	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, h := range rep.Hosts {
		got[h.Host] = h.Sources
	}
	if len(got["a.example.com"]) != 2 {
		t.Errorf("a.example.com sources = %v, want both carried through resolution", got["a.example.com"])
	}
	// Dead hosts keep their lineage too.
	if len(got["b.example.com"]) != 1 {
		t.Errorf("b.example.com sources = %v, want the attribution kept", got["b.example.com"])
	}
}

type attributingEnumerator struct{}

func (attributingEnumerator) Name() string { return "attributing" }
func (attributingEnumerator) Enumerate(context.Context, string) (Enumeration, error) {
	return Enumeration{
		Hosts: []string{"a.example.com", "b.example.com"},
		HostSources: map[string][]string{
			"a.example.com": {"chaos", "crt"},
			"b.example.com": {"crt"},
		},
	}, nil
}

// Targets mode carries no attribution, and the field must stay absent rather
// than appear empty.
func TestNoAttributionLeavesTheFieldAbsent(t *testing.T) {
	cfg := testConfig(t, stage.ScopeEnum)
	stages := Stages{
		Enumerator: fakeEnumerator{hosts: []string{"a.example.com"}},
		Excluder:   fakeExcluder{},
	}
	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hosts[0].Sources != nil {
		t.Errorf("sources = %v, want nil", rep.Hosts[0].Sources)
	}
}

// A consumer needs to know what a missing host means.
func TestRunRecordsWhichInputWasUsed(t *testing.T) {
	cfg := testConfig(t, stage.ScopeEnum)
	stages := Stages{Enumerator: fakeEnumerator{}, Excluder: fakeExcluder{}}

	rep, err := New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Run.Input != report.InputDomain {
		t.Errorf("input = %q, want %q", rep.Run.Input, report.InputDomain)
	}

	cfg.Targets = []string{"a.example.com"}
	rep, err = New(cfg, stages, logging.Discard()).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Run.Input != report.InputTargets {
		t.Errorf("input = %q, want %q", rep.Run.Input, report.InputTargets)
	}
}
