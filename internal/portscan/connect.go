package portscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
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

	// A fixed pool consuming a stream of targets. Spawning one goroutine per
	// probe would allocate a stack for every (address, port) pair up front —
	// a full sweep of fifty addresses is millions of them, and the process is
	// killed for memory long before the deadline it was budgeted.
	queue := make(chan target)
	for range s.opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range queue {
				if ctx.Err() != nil {
					return
				}
				if !s.limiter.Wait(ctx) {
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
