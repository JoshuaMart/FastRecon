package pipeline

import (
	"time"

	"github.com/JoshuaMart/FastRecon/internal/stage"
)

// Stage weights, used to split the remaining time. They are relative, not
// absolute: what matters is their ratio.
//
// Exclusion has weight zero — it is pure CPU work on an in-memory list, so it
// gets no dedicated slice and is bounded only by the global deadline.
var weights = map[stage.Stage]int{
	stage.Enumerate: 25,
	stage.Exclude:   0,
	stage.Resolve:   25,
	stage.PortScan:  30,
	stage.HTTPProbe: 20,
}

// Budget splits the run deadline across the stages still to come.
//
// Allocation is dynamic rather than fixed up front: each stage receives a
// share of the time *actually* left, so an enumeration that finishes early
// hands its unused seconds to the port scan instead of wasting them.
type Budget struct {
	deadline  time.Time
	remaining []stage.Stage
	now       func() time.Time
}

// NewBudget builds a budget over the stages of a scope.
func NewBudget(stages []stage.Stage, deadline time.Time) *Budget {
	return &Budget{
		deadline:  deadline,
		remaining: append([]stage.Stage(nil), stages...),
		now:       time.Now,
	}
}

// Left is the time until the run deadline, never negative.
func (b *Budget) Left() time.Duration {
	return max(b.deadline.Sub(b.now()), 0)
}

// Expired reports whether the deadline has passed.
func (b *Budget) Expired() bool { return b.Left() <= 0 }

// Deadline returns the run deadline.
func (b *Budget) Deadline() time.Time { return b.deadline }

// Take allocates s its share of the remaining time and marks it, and every
// stage before it, as consumed. A zero-weight stage gets everything that is
// left, meaning "no dedicated budget".
func (b *Budget) Take(s stage.Stage) time.Duration {
	left := b.Left()
	total := 0
	found := false
	for _, r := range b.remaining {
		if r == s {
			found = true
		}
		if found {
			total += weights[r]
		}
	}
	b.consume(s)

	if !found || total == 0 || weights[s] == 0 {
		return left
	}
	return time.Duration(float64(left) * float64(weights[s]) / float64(total))
}

func (b *Budget) consume(s stage.Stage) {
	for i, r := range b.remaining {
		if r == s {
			b.remaining = b.remaining[i+1:]
			return
		}
	}
}
