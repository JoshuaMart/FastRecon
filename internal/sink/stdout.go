package sink

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Stdout writes the report to standard output. Logs never go here — that is
// what keeps `fastrecon ... | jq` working and the job's logs readable.
type Stdout struct {
	w io.Writer
}

// NewStdout builds the stdout sink.
func NewStdout() *Stdout { return &Stdout{w: os.Stdout} }

// NewWriter builds a sink writing to an arbitrary writer, for tests.
func NewWriter(w io.Writer) *Stdout { return &Stdout{w: w} }

func (s *Stdout) Name() string { return "stdout" }

func (s *Stdout) Deliver(_ context.Context, data []byte) error {
	if _, err := s.w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}
