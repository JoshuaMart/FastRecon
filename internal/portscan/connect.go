package portscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// scanConnect performs a TCP connect scan.
//
// Connect scanning needs no privileges, which is the whole reason it is the
// default: it is the only mode that works in a serverless job. A completed
// handshake means the port is open; a refusal means it is closed; a timeout
// means it is filtered, and only that case is worth retrying.
func (s *Scanner) scanConnect(ctx context.Context, addresses []string, ports portSpec) (map[string][]int, error) {
	list, err := s.expand(ports)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 || len(addresses) == 0 {
		return map[string][]int{}, nil
	}

	targets := plan(addresses, list)
	s.opts.Logger.Debug("connect scan started",
		"addresses", len(addresses),
		"ports", len(list),
		"probes", len(targets),
		"concurrency", s.opts.Concurrency,
		"rate", s.opts.Rate,
	)

	var (
		found = map[string][]int{}
		mu    sync.Mutex
		wg    sync.WaitGroup
		sem   = make(chan struct{}, s.opts.Concurrency)
	)
	limiter := newLimiter(s.opts.Rate)
	defer limiter.stop()

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if !limiter.wait(ctx) {
				return
			}
			if s.probe(ctx, t) {
				mu.Lock()
				found[t.address] = append(found[t.address], t.port)
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()

	return found, nil
}

type target struct {
	address string
	port    int
}

// plan orders the probes port-major: every address is tried on one port
// before moving to the next. Address-major order would hammer a single host
// with the whole port list back to back.
func plan(addresses []string, ports []int) []target {
	out := make([]target, 0, len(addresses)*len(ports))
	for _, p := range ports {
		for _, a := range addresses {
			out = append(out, target{address: a, port: p})
		}
	}
	return out
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
	}
	return false
}

// isInconclusive reports whether an error leaves the port's state unknown.
func isInconclusive(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Local resource exhaustion says nothing about the target either.
	return errors.Is(err, syscallEMFILE) || errors.Is(err, syscallENFILE)
}

// limiter is a token bucket capping probes per second. A scan that ignores
// rate is indistinguishable from an attack from the target's side.
type limiter struct {
	tokens chan struct{}
	done   chan struct{}
	once   sync.Once
}

func newLimiter(perSecond int) *limiter {
	l := &limiter{
		tokens: make(chan struct{}, max(perSecond/10, 1)),
		done:   make(chan struct{}),
	}
	if perSecond <= 0 {
		close(l.done)
		return l
	}

	interval := time.Second / time.Duration(perSecond)
	// Below the timer's practical resolution, refill in batches instead of
	// ticking per token.
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

// wait blocks for a token, reporting false if the run ended first.
func (l *limiter) wait(ctx context.Context) bool {
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

func (l *limiter) stop() { l.once.Do(func() { close(l.done) }) }
