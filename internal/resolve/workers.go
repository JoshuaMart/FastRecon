package resolve

import (
	"context"
	"sync"
)

// workers runs fn over the indexes 0..n-1 on a pool of at most limit
// goroutines, and returns how many indexes were never started because ctx
// ended first.
//
// A goroutine per item with a semaphore inside would be shorter, but the item
// count here is the enumeration output: one goroutine per host means a
// hundred thousand goroutines parked on a channel before a single query goes
// out, and their stacks are allocated whether or not the work ever starts.
// The pool is what the port scan and the HTTP probe already do, and this
// package is the only one that did not.
//
// Callers pre-fill their result slice with the "not reached" value, so an
// index fn never runs for keeps a meaningful entry rather than a zero one.
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
			// The queue is drained rather than abandoned: leaving it would
			// block the feeder, and the count of what was skipped is itself a
			// result the report carries.
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
