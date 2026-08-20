// Package ratelimit caps how fast a stage issues probes.
//
// A scan or a probe sweep that ignores rate is indistinguishable, from the
// target's side, from an attack.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token bucket. A zero or negative rate disables it, in which
// case Wait never blocks.
type Limiter struct {
	tokens chan struct{}
	done   chan struct{}
	once   sync.Once
}

// New starts a limiter delivering perSecond tokens per second.
func New(perSecond int) *Limiter {
	l := &Limiter{
		tokens: make(chan struct{}, max(perSecond/10, 1)),
		done:   make(chan struct{}),
	}
	if perSecond <= 0 {
		// Through the once, so a later Stop is not a second close.
		l.Stop()
		return l
	}

	interval := time.Second / time.Duration(perSecond)
	// Below the timer's practical resolution, refill in batches instead of
	// ticking once per token.
	batch := 1
	if interval < time.Millisecond {
		batch = int(time.Millisecond / interval)
		interval = time.Millisecond
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				for range batch {
					select {
					case l.tokens <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return l
}

// Wait blocks for a token, reporting false if ctx ended first.
func (l *Limiter) Wait(ctx context.Context) bool {
	select {
	case <-l.done:
		return true
	default:
	}
	select {
	case <-l.tokens:
		return true
	case <-ctx.Done():
		return false
	}
}

// Stop releases the limiter's ticker.
func (l *Limiter) Stop() { l.once.Do(func() { close(l.done) }) }
