package resolve

import (
	"context"
	"sync"
)

// workers runs fn over the indexes 0..n-1 on a pool of at most limit
// goroutines, and returns how many indexes were never started because ctx
// ended first.
//
// It is a fixed pool, not a goroutine per item behind a semaphore: the item
// count is the enumeration output, and a hundred thousand parked goroutines
// allocate their stacks before a single query goes out.
//
// Callers pre-fill their result slice with the "not reached" value, so an
// index fn never runs for keeps a meaningful entry.
func workers(ctx context.Context, n, limit int, fn func(i int)) int {
	if n <= 0 {
		return 0
	}
	if limit < 1 {
		limit = 1
	}
	limit = min(limit, n)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		unstarted int
	)
	skip := func() {
		mu.Lock()
		unstarted++
		mu.Unlock()
	}

	queue := make(chan int)
	for range limit {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Drain rather than abandon the queue: leaving it would block the
			// feeder, and the skipped count is reported.
			for i := range queue {
				if ctx.Err() != nil {
					skip()
					continue
				}
				fn(i)
			}
		}()
	}

	for i := range n {
		select {
		case queue <- i:
		case <-ctx.Done():
			skip()
		}
	}
	close(queue)
	wg.Wait()

	return unstarted
}
