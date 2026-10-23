package portscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/ratelimit"
	"github.com/JoshuaMart/FastRecon/internal/report"
)

// scanConnect performs TCP connect scan (no privileges needed; only serverless-compatible mode).
// Handshake=open, refusal=closed, timeout=filtered (only filtered worth retrying).
// scanResult pairs the open ports with what each address was actually probed
// for, so an empty port list is distinguishable from an absent sweep.
type scanResult struct {
	open  map[string][]int
	tally map[string]*report.Scan
}

func (s *Scanner) scanConnect(ctx context.Context, addresses []string, ports portSpec, limiter *ratelimit.Limiter) (scanResult, error) {
	list, err := s.expand(ports)
	if err != nil {
		return scanResult{}, err
	}
	if len(list) == 0 || len(addresses) == 0 {
		return scanResult{open: map[string][]int{}, tally: map[string]*report.Scan{}}, nil
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
		tally = map[string]*report.Scan{}
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
				res := s.probe(ctx, t)
				if res == outcomeSkipped {
					continue
				}
				mu.Lock()
				count(tally, t.address, res)
				if res == outcomeOpen {
					found[t.address] = append(found[t.address], t.port)
				}
				mu.Unlock()
			}
		}()
	}

	feed(ctx, queue, addresses, list)
	wg.Wait()

	return scanResult{open: found, tally: tally}, nil
}

// count records one concluded probe. Scanned tracks attempts, so the four
// buckets always sum to it.
func count(tally map[string]*report.Scan, address string, res outcome) {
	t := tally[address]
	if t == nil {
		t = &report.Scan{}
		tally[address] = t
	}
	t.Scanned++
	switch res {
	case outcomeOpen:
		t.Open++
	case outcomeRefused:
		t.Refused++
	case outcomeFiltered:
		t.Filtered++
	case outcomeUnknown:
		t.Unknown++
	}
}

type target struct {
	address string
	port    int
}

// feed streams the probes port-major: every address is tried on one port
// before moving to the next. Address-major order would hammer a single host
// with the whole port list back to back.
//
// Targets are generated, not materialised: the full list of a wide sweep is
// itself too large to hold.
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
// outcome is what one probe concluded. The four are kept apart because a
// report that only lists open ports says the same thing for opposite
// findings: nothing listening and nothing attempted.
type outcome int

const (
	// outcomeSkipped is a probe the run never made; it counts as nothing.
	outcomeSkipped outcome = iota
	outcomeOpen
	outcomeRefused
	outcomeFiltered
	// outcomeUnknown is a local limit, which says nothing about the target.
	outcomeUnknown
)

func (s *Scanner) probe(ctx context.Context, t target) outcome {
	addr := net.JoinHostPort(t.address, strconv.Itoa(t.port))
	dialer := &net.Dialer{Timeout: s.opts.Timeout}

	last := outcomeSkipped
	for attempt := 0; attempt <= s.opts.Retries; attempt++ {
		if ctx.Err() != nil {
			return last
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return outcomeOpen
		}
		// A dial cut short by the run's own end — a deadline, a signal, a
		// caller gone — was never answered. It is not a verdict.
		if ctx.Err() != nil {
			return last
		}
		res, retry := outcomeOf(err)
		last = res
		if !retry {
			return last
		}
		// A timeout already cost a full dial budget, which is backoff enough.
		// Descriptor exhaustion did not: with every worker retrying at once,
		// an immediate retry just hits the same ceiling.
		if isExhausted(err) && !sleepCtx(ctx, exhaustionBackoff) {
			return last
		}
	}
	return last
}

// outcomeOf turns a failed dial into what it says about the port, and whether
// another attempt could say something different.
//
// Only a refusal means closed. Anything else that is not a timeout (no route,
// a local limit, an unexpected error) says nothing about the port; recording
// it as refused would turn "could not look" into "nothing listening".
func outcomeOf(err error) (res outcome, retry bool) {
	switch {
	case isExhausted(err):
		return outcomeUnknown, true
	case isInconclusive(err):
		return outcomeFiltered, true
	case errors.Is(err, syscallEHOSTUNREACH):
		return outcomeFiltered, false
	case errors.Is(err, syscallENETUNREACH):
		return outcomeUnknown, false
	case isRefused(err):
		// A definitive answer: retrying would multiply the work for no new
		// information.
		return outcomeRefused, false
	default:
		return outcomeUnknown, false
	}
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
	return errors.Is(err, syscallEMFILE) || errors.Is(err, syscallENFILE) || errors.Is(err, syscallEADDRNOTAVAIL)
}
