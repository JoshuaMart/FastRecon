package sink

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(99)}))
}

// newTestWebhook builds a webhook whose backoff does not actually wait.
func newTestWebhook(t *testing.T, opts WebhookOptions) (*Webhook, *[]time.Duration) {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	opts.Logger = discardLogger()

	w, err := NewWebhook(opts)
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	var waits []time.Duration
	w.sleep = func(ctx context.Context, d time.Duration) bool {
		waits = append(waits, d)
		return ctx.Err() == nil
	}
	return w, &waits
}

func TestWebhookSendsTheReportAsJSON(t *testing.T) {
	var (
		gotBody   string
		gotMethod string
		gotAuth   string
		gotType   string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody, gotMethod = string(body), r.Method
		gotAuth = r.Header.Get("Authorization")
		gotType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	wh, _ := newTestWebhook(t, WebhookOptions{
		URL:     srv.URL,
		Headers: []string{"Authorization: Bearer token"},
	})
	if err := wh.Deliver(context.Background(), []byte(`{"schema_version":"1.0"}`)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if gotBody != `{"schema_version":"1.0"}` {
		t.Errorf("body = %q, want the report unchanged", gotBody)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Bearer token" {
		t.Errorf("authorization = %q, want the configured header", gotAuth)
	}
	if gotType != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotType)
	}
}

func TestWebhookRetriesServerErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh, waits := newTestWebhook(t, WebhookOptions{URL: srv.URL, Retries: 3})
	if err := wh.Deliver(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
	// Backoff must grow, or a struggling endpoint gets hammered.
	if len(*waits) != 2 || (*waits)[1] <= (*waits)[0] {
		t.Errorf("waits = %v, want an increasing backoff", *waits)
	}
}

// A 4xx will not become valid on a retry: the request itself is wrong.
func TestWebhookDoesNotRetryClientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	wh, _ := newTestWebhook(t, WebhookOptions{URL: srv.URL, Retries: 5})
	err := wh.Deliver(context.Background(), []byte("{}"))
	if err == nil {
		t.Fatal("Deliver reported success on a 403")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want exactly one", got)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want the status named", err)
	}
}

// 429 is the server saying "not now", unlike every other 4xx.
func TestWebhookRetriesRateLimits(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh, waits := newTestWebhook(t, WebhookOptions{URL: srv.URL, Retries: 2})
	if err := wh.Deliver(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	// The endpoint asked for a specific wait; it knows better than the schedule.
	if len(*waits) != 1 || (*waits)[0] != 7*time.Second {
		t.Errorf("waits = %v, want the requested 7s honoured", *waits)
	}
}

func TestWebhookRetriesTransportFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening any more

	wh, waits := newTestWebhook(t, WebhookOptions{URL: url, Retries: 2, Timeout: 500 * time.Millisecond})
	err := wh.Deliver(context.Background(), []byte("{}"))
	if err == nil {
		t.Fatal("Deliver reported success against a dead endpoint")
	}
	if len(*waits) != 2 {
		t.Errorf("waits = %v, want both retries attempted", *waits)
	}
	if !strings.Contains(err.Error(), "attempt") {
		t.Errorf("error = %q, want it to say how many attempts were made", err)
	}
}

func TestWebhookStopsWhenTheDeliveryBudgetEnds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wh, _ := newTestWebhook(t, WebhookOptions{URL: srv.URL, Retries: 10})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := wh.Deliver(ctx, []byte("{}"))
	if err == nil {
		t.Fatal("Deliver reported success after its budget ended")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to carry the cancellation", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("12"); got != 12*time.Second {
		t.Errorf("seconds form = %s, want 12s", got)
	}
	future := time.Now().Add(20 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got <= 0 || got > 21*time.Second {
		t.Errorf("date form = %s, want roughly 20s", got)
	}
	for _, in := range []string{"", "soon", "-5", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)} {
		if got := parseRetryAfter(in); got != 0 {
			t.Errorf("parseRetryAfter(%q) = %s, want 0", in, got)
		}
	}
}

func TestBackoffIsCapped(t *testing.T) {
	// The shift overflows int64 past ~35 attempts; a negative duration then
	// panics the jitter, crashing the process after the report was produced.
	for _, attempt := range []int{1, 2, 16, 20, 35, 64, 1000} {
		got := backoff(attempt, 0)
		if got <= 0 || got > maxBackoff {
			t.Errorf("backoff(%d) = %s, want a positive wait within %s", attempt, got, maxBackoff)
		}
	}
	if got := backoff(1, time.Hour); got != maxBackoff {
		t.Errorf("a huge Retry-After gave %s, want it capped at %s", got, maxBackoff)
	}
}

func TestNewWebhookRejectsUnusableOptions(t *testing.T) {
	base := WebhookOptions{URL: "https://example.net/hook", Timeout: time.Second, Logger: discardLogger()}
	for name, mutate := range map[string]func(*WebhookOptions){
		"no logger":        func(o *WebhookOptions) { o.Logger = nil },
		"no url":           func(o *WebhookOptions) { o.URL = "" },
		"no timeout":       func(o *WebhookOptions) { o.Timeout = 0 },
		"negative retries": func(o *WebhookOptions) { o.Retries = -1 },
		"bad header":       func(o *WebhookOptions) { o.Headers = []string{"nope"} },
	} {
		opts := base
		mutate(&opts)
		if _, err := NewWebhook(opts); err == nil {
			t.Errorf("NewWebhook accepted options with %s", name)
		}
	}
}
