package pipeline

import (
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/stage"
)

func fixedBudget(stages []stage.Stage, total time.Duration) (*Budget, *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := now
	b := NewBudget(stages, now.Add(total))
	b.now = func() time.Time { return clock }
	return b, &clock
}

func TestTakeSplitsByWeight(t *testing.T) {
	b, _ := fixedBudget(stage.ScopeFull.Stages(), 100*time.Minute)

	// enumerate weighs 25 of the 100 total across the full ladder.
	if got := b.Take(stage.Enumerate); got != 25*time.Minute {
		t.Errorf("enumerate budget = %s, want 25m", got)
	}
	// exclude is CPU-only: no dedicated slice, bounded by the deadline.
	if got := b.Take(stage.Exclude); got != 100*time.Minute {
		t.Errorf("exclude budget = %s, want the whole remaining window", got)
	}
}

func TestTakeReallocatesTimeUnusedByEarlierStages(t *testing.T) {
	stages := stage.ScopeFull.Stages()
	b, clock := fixedBudget(stages, 100*time.Minute)

	b.Take(stage.Enumerate)
	b.Take(stage.Exclude)
	// Enumeration finished instantly, so resolve should get a share of the
	// full 100 minutes rather than of the 75 it was nominally left.
	got := b.Take(stage.Resolve)
	if got != time.Duration(float64(100*time.Minute)*25.0/75.0) {
		t.Errorf("resolve budget = %s, want 25/75 of the remaining 100m", got)
	}

	// And a stage that overran must shrink what follows.
	*clock = clock.Add(90 * time.Minute)
	if got := b.Take(stage.PortScan); got >= 10*time.Minute {
		t.Errorf("portscan budget = %s, want less than the 10m actually left", got)
	}
}

func TestExpired(t *testing.T) {
	b, clock := fixedBudget(stage.ScopeEnum.Stages(), time.Minute)
	if b.Expired() {
		t.Fatal("budget expired before any time passed")
	}
	*clock = clock.Add(2 * time.Minute)
	if !b.Expired() {
		t.Error("budget not expired past its deadline")
	}
	if got := b.Left(); got != 0 {
		t.Errorf("Left() = %s past the deadline, want 0", got)
	}
}
