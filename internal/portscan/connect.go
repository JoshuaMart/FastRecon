package portscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/ratelimit"
)

// scanConnect performs TCP connect scan (no privileges needed; only serverless-compatible mode).
// Handshake=open, refusal=closed, timeout=filtered (only filtered worth retrying).
func (s *Scanner) scanConnect(ctx context.Context, addresses []string, ports portSpec, limiter *ratelimit.Limiter) (map[string][]int, error) {
	list, err := s.expand(ports)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 || len(addresses) == 0 {
		return map[string][]int{}, nil
	}

	s.opts.Logger.Debug("connect scan started",
		"addresses", len(addresses),
		"ports", len(list),
		"probes", len(addresses)*len(list),
		"concurrency", s.opts.Concurrency,
		"rate", s.opts.Rate,
	)

	var (
		found = map[string][]int{}
		mu    sync.Mutex
		wg    sync.WaitGroup
	)

	// Fixed pool (not per-probe goroutines; would OOM on large sweeps).
	queue := make(chan target)
	for range s.opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range queue {
				if ctx.Err() != nil {
					return
				}
				if !limiter.Wait(ctx) {
					return
				}
				if s.probe(ctx, t) {
					mu.Lock()
					found[t.address] = append(found[t.address], t.port)
					mu.Unlock()
				}
			}
		}()
	}

	feed(ctx, queue, addresses, list)
	wg.Wait()

	return found, nil
}

type target struct {
	address string
	port    int
}

// feed streams the probes port-major: every address is tried on one port
// before moving to the next. Address-major order would hammer a single host
// with the whole port list back to back.
//
// Targets are generated rather than materialised: the full list for a wide
// sweep is itself large enough to be worth not holding.
func feed(ctx context.Context, queue chan<- target, addresses []string, ports []int) {
	defer close(queue)
	for _, p := range ports {
		for _, a := range addresses {
			select {
			case queue <- target{address: a, port: p}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// probe reports whether a TCP handshake completes, retrying only the
// inconclusive cases.
func (s *Scanner) probe(ctx context.Context, t target) bool {
	addr := net.JoinHostPort(t.address, strconv.Itoa(t.port))
	dialer := &net.Dialer{Timeout: s.opts.Timeout}

	for attempt := 0; attempt <= s.opts.Retries; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return true
		}
		// A refusal is a definitive answer: the port is closed. Retrying it
		// would multiply the work for no new information.
		if !isInconclusive(err) {
			return false
		}
		// A timeout already cost a full dial budget, which is backoff enough.
		// Running out of file descriptors did not: retrying that immediately
		// only spends the next attempt hitting the same ceiling, and with
		// every worker doing it at once the ceiling does not move.
		if isExhausted(err) && !sleepCtx(ctx, exhaustionBackoff) {
			return false
		}
	}
	return false
}

// exhaustionBackoff is how long a probe waits after running out of local file
// descriptors, giving the ones in flight time to be released.
const exhaustionBackoff = 100 * time.Millisecond

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// isInconclusive reports whether an error leaves the port's state unknown.
func isInconclusive(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Local resource exhaustion says nothing about the target either.
	return isExhausted(err)
}

// isExhausted reports whether the probe failed on a local limit rather than
// on anything the target did.
func isExhausted(err error) bool {
	return errors.Is(err, syscallEMFILE) || errors.Is(err, syscallENFILE)
}
