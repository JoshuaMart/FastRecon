//go:build unix

package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func dialError(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

// Only the target turning the connection down means closed. Anything that
// says nothing about the port must not be counted as a refusal.
func TestOutcomeOfDialErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err   error
		want  outcome
		retry bool
	}{
		"refused":           {dialError(syscall.ECONNREFUSED), outcomeRefused, false},
		"no route":          {dialError(syscall.ENETUNREACH), outcomeUnknown, false},
		"host unreachable":  {dialError(syscall.EHOSTUNREACH), outcomeFiltered, false},
		"ephemeral ports":   {dialError(syscall.EADDRNOTAVAIL), outcomeUnknown, true},
		"file descriptors":  {dialError(syscall.EMFILE), outcomeUnknown, true},
		"unanticipated":     {errors.New("something else"), outcomeUnknown, false},
		"permission denied": {dialError(syscall.EACCES), outcomeUnknown, false},
	} {
		got, retry := outcomeOf(tc.err)
		if got != tc.want || retry != tc.retry {
			t.Errorf("%s: outcome = %v (retry %v), want %v (retry %v)", name, got, retry, tc.want, tc.retry)
		}
	}
}

// A dial the run itself abandoned was never answered, and must not inflate
// the refused count of a report written on SIGTERM.
func TestCanceledDialIsNotAVerdict(t *testing.T) {
	// TEST-NET-1 is routed nowhere: where a default route exists the dial
	// hangs, which is the window the cancellation has to land in.
	probe, err := net.DialTimeout("tcp", "192.0.2.1:9", 200*time.Millisecond)
	if err == nil {
		_ = probe.Close()
		t.Skip("192.0.2.1 answered here")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Skip("no route to TEST-NET-1 here:", err)
	}

	s, err := New(Options{Mode: ModeConnect, Ports: "9", Concurrency: 1, Rate: 1, Timeout: 10 * time.Second, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	if got := s.probe(ctx, target{address: "192.0.2.1", port: 9}); got != outcomeSkipped {
		t.Errorf("outcome = %v, want skipped for a dial the run canceled", got)
	}
}
