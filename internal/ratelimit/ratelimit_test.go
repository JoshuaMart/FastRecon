package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestLimiterCapsThroughput(t *testing.T) {
	l := New(200)
	defer l.Stop()

	start := time.Now()
	for range 40 {
		if !l.Wait(context.Background()) {
			t.Fatal("Wait returned false on a live context")
		}
	}
	// 40 tokens at 200/s cannot arrive in much under 100ms once the initial
	// bucket is drained.
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Errorf("40 tokens took %s at 200/s, want the rate to bite", elapsed)
	}
}

// A disabled limiter must not block, or a stage configured without a rate
// would stall forever.
func TestZeroRateNeverBlocks(t *testing.T) {
	l := New(0)
	defer l.Stop()

	done := make(chan struct{})
	go func() {
		for range 1000 {
			l.Wait(context.Background())
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a zero rate blocked")
	}
}

func TestWaitReleasesOnContextEnd(t *testing.T) {
	l := New(1)
	defer l.Stop()

	// Drain whatever the bucket starts with.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	for l.Wait(ctx) {
	}

	if l.Wait(ctx) {
		t.Error("Wait returned true after its context ended")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	l := New(10)
	l.Stop()
	l.Stop()
}
