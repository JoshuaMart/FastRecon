// Package sink delivers a rendered report to its destinations.
//
// Every sink receives the same bytes: the report is rendered once, so no
// consumer can end up with a different shape than another.
package sink

import (
	"context"
	"errors"
	"fmt"
)

// Sink is one report destination.
type Sink interface {
	Name() string
	Deliver(ctx context.Context, data []byte) error
}

// Result is the outcome of one delivery.
type Result struct {
	Sink string
	Err  error
}

// DeliverAll writes to every sink and returns the failures. One failing sink
// never stops the others: a report that reached stdout is still a delivered
// report even if the webhook was down.
func DeliverAll(ctx context.Context, data []byte, sinks []Sink) []Result {
	results := make([]Result, 0, len(sinks))
	for _, s := range sinks {
		err := s.Deliver(ctx, data)
		if err != nil {
			err = fmt.Errorf("%s sink: %w", s.Name(), err)
		}
		results = append(results, Result{Sink: s.Name(), Err: err})
	}
	return results
}

// Errs collects the delivery failures.
func Errs(results []Result) error {
	var errs []error
	for _, r := range results {
		if r.Err != nil {
			errs = append(errs, r.Err)
		}
	}
	return errors.Join(errs...)
}
