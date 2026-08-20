package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookOptions configures the webhook sink.
type WebhookOptions struct {
	URL     string
	Method  string
	Headers []string
	Timeout time.Duration
	// Retries is the number of extra attempts after the first.
	Retries int
	Logger  *slog.Logger
}

// Webhook POSTs the report to an HTTP endpoint.
//
// The payload is the report document exactly as the other sinks emit it: one
// shape for every consumer, no per-destination formatting.
type Webhook struct {
	url     string
	method  string
	headers map[string][]string
	retries int
	log     *slog.Logger
	client  *http.Client
	// sleep is the backoff wait, replaced in tests.
	sleep func(ctx context.Context, d time.Duration) bool
}

// maxBackoff caps the exponential wait so a long retry chain cannot outlive
// the deadline it is running under.
const maxBackoff = 30 * time.Second

// NewWebhook builds the sink.
func NewWebhook(opts WebhookOptions) (*Webhook, error) {
	if opts.Logger == nil {
		return nil, errors.New("webhook: logger is required")
	}
	if opts.URL == "" {
		return nil, errors.New("webhook: url is required")
	}
	if opts.Timeout <= 0 {
		return nil, errors.New("webhook: timeout must be positive")
	}
	if opts.Retries < 0 {
		return nil, errors.New("webhook: retries must not be negative")
	}

	headers, err := parseHeaders(opts.Headers)
	if err != nil {
		return nil, fmt.Errorf("webhook: %w", err)
	}

	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		method = http.MethodPost
	}

	return &Webhook{
		url:     opts.URL,
		method:  method,
		headers: headers,
		retries: opts.Retries,
		log:     opts.Logger,
		client:  &http.Client{Timeout: opts.Timeout},
		sleep:   sleepCtx,
	}, nil
}

func (w *Webhook) Name() string { return "webhook" }

// Deliver POSTs the report, retrying the failures that can plausibly succeed
// on a second try.
func (w *Webhook) Deliver(ctx context.Context, data []byte) error {
	var lastErr error

	for attempt := 0; attempt <= w.retries; attempt++ {
		if attempt > 0 {
			wait := backoff(attempt, retryAfter(lastErr))
			w.log.Debug("webhook retry", "attempt", attempt, "wait", wait.String())
			if !w.sleep(ctx, wait) {
				return fmt.Errorf("delivery abandoned: %w", ctx.Err())
			}
		}

		status, err := w.post(ctx, data)
		if err == nil {
			w.log.Debug("webhook delivered", "status", status, "attempt", attempt+1)
			return nil
		}
		lastErr = err

		if !retryable(err) {
			// A 4xx will not become valid on a retry; the request itself is
			// wrong, most often the credentials or the URL.
			return err
		}
	}
	return fmt.Errorf("after %d attempt(s): %w", w.retries+1, lastErr)
}

func (w *Webhook) post(ctx context.Context, data []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for name, values := range w.headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return 0, transportError{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	// The body is drained so the connection can be reused; its contents are
	// not reported, since a webhook target may echo the payload back.
	_, _ = readAndDiscard(resp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, statusError{
		status:     resp.StatusCode,
		retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
}

// transportError is a failure to reach the endpoint at all.
type transportError struct{ err error }

func (e transportError) Error() string { return "transport: " + e.err.Error() }
func (e transportError) Unwrap() error { return e.err }

// statusError is a non-2xx response.
type statusError struct {
	status     int
	retryAfter time.Duration
}

func (e statusError) Error() string { return "unexpected status " + strconv.Itoa(e.status) }

// retryable reports whether another attempt could plausibly succeed.
func retryable(err error) bool {
	var status statusError
	if errors.As(err, &status) {
		// 429 and 5xx are the server saying "not now"; every other 4xx is it
		// saying "not like this".
		return status.status == http.StatusTooManyRequests || status.status >= 500
	}
	var transport transportError
	return errors.As(err, &transport)
}

// retryAfter extracts a server-requested wait, if the last failure carried one.
func retryAfter(err error) time.Duration {
	var status statusError
	if errors.As(err, &status) {
		return status.retryAfter
	}
	return 0
}

// backoff grows exponentially with jitter, but honours a server-requested
// wait when there is one: the endpoint knows better than the schedule.
func backoff(attempt int, requested time.Duration) time.Duration {
	if requested > 0 {
		return min(requested, maxBackoff)
	}
	wait := time.Second << (attempt - 1)
	wait = min(wait, maxBackoff)
	// Jitter keeps several jobs retrying in lockstep from synchronising.
	return wait/2 + time.Duration(rand.Int64N(int64(wait/2)+1))
}

// parseRetryAfter reads the header in both of its forms: seconds, or a date.
func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

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

// parseHeaders turns "Name: value" entries into a header map.
func parseHeaders(headers []string) (map[string][]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(headers))
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, fmt.Errorf("header %q must be in 'Name: value' form", h)
		}
		out[name] = append(out[name], value)
	}
	return out, nil
}
