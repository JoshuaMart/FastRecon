package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/JoshuaMart/FastRecon/internal/app"
	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
	"github.com/JoshuaMart/FastRecon/internal/stage"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(99)}))
}

// fakeRunner records what it was asked to run and answers without a network.
type fakeRunner struct {
	cfg *config.Config

	mu      sync.Mutex
	lastCfg *config.Config
	calls   int

	block chan struct{}
	err   error
}

func (f *fakeRunner) Config() *config.Config      { return f.cfg }
func (f *fakeRunner) Redactor() *secrets.Redactor { return secrets.NewRedactor(nil) }
func (f *fakeRunner) Run(ctx context.Context, cfg *config.Config) (*report.Report, error) {
	f.mu.Lock()
	f.calls++
	f.lastCfg = cfg
	f.mu.Unlock()

	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	rep := report.New("01TEST", cfg.Domain, report.InputDomain, cfg.Scope, "test", cfg.Environment, time.Now())
	rep.Finish(time.Now())
	return rep, nil
}

func newTestServer(t *testing.T, runner *fakeRunner) *Server {
	t.Helper()
	if runner.cfg == nil {
		runner.cfg = baseConfig(t)
	}
	s, err := New(runner, &config.Config{APIToken: "secret"}, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// baseConfig is the real default configuration, built the way the binary
// builds it. Hand-writing a valid Config here would drift the moment an
// option is added, and the test would then be validating a shape nothing
// else uses.
func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	cfg, err := config.LoadServe(fs)
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	cfg.Environment = config.EnvServerlessFunction
	return cfg
}

func post(t *testing.T, s *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// An open subdomain-enumeration endpoint is free reconnaissance for whoever
// finds it, charged to this deployment's quotas.
func TestNewRefusesWithoutAToken(t *testing.T) {
	if _, err := New(&fakeRunner{cfg: baseConfig(t)}, &config.Config{}, discardLogger()); err == nil {
		t.Fatal("New accepted an empty token")
	}
	if _, err := New(&fakeRunner{cfg: baseConfig(t)}, &config.Config{APIToken: "  "}, discardLogger()); err == nil {
		t.Error("New accepted a blank token")
	}
}

func TestAuthorization(t *testing.T) {
	runner := &fakeRunner{}
	s := newTestServer(t, runner)

	for name, token := range map[string]string{
		"no token":    "",
		"wrong token": "nope",
	} {
		if got := post(t, s, token, `{"domain":"example.com"}`).Code; got != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, got)
		}
	}
	if runner.calls != 0 {
		t.Error("an unauthorized request reached the pipeline")
	}

	// A malformed header must not be mistaken for a valid one.
	req := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(`{"domain":"example.com"}`))
	req.Header.Set("Authorization", "secret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bare token without the Bearer prefix: status = %d, want 401", rec.Code)
	}

	if got := post(t, s, "secret", `{"domain":"example.com"}`).Code; got != http.StatusOK {
		t.Errorf("valid token: status = %d, want 200", got)
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	s := newTestServer(t, &fakeRunner{})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequestOverlaysOntoTheProcessConfiguration(t *testing.T) {
	runner := &fakeRunner{}
	s := newTestServer(t, runner)

	rec := post(t, s, "secret", `{"domain":"Example.COM","stages":"enum","ports":"80,443","exclude":["*.dev.example.com"],"timeout":"90s"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	got := runner.lastCfg
	if got.Domain != "example.com" {
		t.Errorf("domain = %q, want it normalized", got.Domain)
	}
	if got.Scope != stage.ScopeEnum || got.Ports != "80,443" {
		t.Errorf("scope/ports = %v/%q, want the request values", got.Scope, got.Ports)
	}
	if len(got.Exclude) != 1 || got.Exclude[0] != "*.dev.example.com" {
		t.Errorf("exclude = %v, want the request value", got.Exclude)
	}
	if got.Timeout != 90*time.Second {
		t.Errorf("timeout = %s, want 90s", got.Timeout)
	}
	// Untouched fields keep the deployment's configuration.
	if got.ScanRate != runner.cfg.ScanRate {
		t.Errorf("scan rate = %d, want the process value %d", got.ScanRate, runner.cfg.ScanRate)
	}
}

// A request must not be able to leave its exclusions behind in the process
// configuration for the next caller.
func TestRequestsDoNotLeakIntoEachOther(t *testing.T) {
	runner := &fakeRunner{}
	s := newTestServer(t, runner)

	post(t, s, "secret", `{"domain":"example.com","exclude":["admin.example.com"]}`)
	post(t, s, "secret", `{"domain":"example.net"}`)

	if len(runner.lastCfg.Exclude) != 0 {
		t.Errorf("second request inherited %v from the first", runner.lastCfg.Exclude)
	}
	if len(runner.cfg.Exclude) != 0 {
		t.Errorf("the process configuration was mutated: %v", runner.cfg.Exclude)
	}
}

func TestInvalidRequests(t *testing.T) {
	s := newTestServer(t, &fakeRunner{})

	cases := map[string]string{
		"not json":        `{`,
		"empty domain":    `{}`,
		"domain is a url": `{"domain":"https://example.com/x"}`,
		"unknown scope":   `{"domain":"example.com","stages":"everything"}`,
		"bad duration":    `{"domain":"example.com","timeout":"soon"}`,
		// A caller believing they configured a destination must be told they
		// did not, rather than have it silently ignored.
		"webhook url": `{"domain":"example.com","webhook_url":"http://elsewhere"}`,
		"credentials": `{"domain":"example.com","sources":["chaos"]}`,
	}
	for name, body := range cases {
		rec := post(t, s, "secret", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", name, rec.Code, rec.Body)
		}
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	s := newTestServer(t, &fakeRunner{})
	huge := `{"domain":"example.com","exclude":["` + strings.Repeat("a", maxBodyBytes+1) + `"]}`
	if got := post(t, s, "secret", huge).Code; got != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", got)
	}
}

// Refused rather than queued: a queued request spends its own deadline
// waiting and then reports a timeout that explains nothing.
func TestSecondConcurrentRunIsRefused(t *testing.T) {
	runner := &fakeRunner{block: make(chan struct{})}
	s := newTestServer(t, runner)

	started := make(chan struct{})
	go func() {
		close(started)
		post(t, s, "secret", `{"domain":"example.com"}`)
	}()
	<-started
	// Let the first request take the lock.
	for range 100 {
		runner.mu.Lock()
		n := runner.calls
		runner.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	rec := post(t, s, "secret", `{"domain":"example.net"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a refusal must tell the caller when to come back")
	}
	close(runner.block)
}

// The same split the exit codes make: a transient failure is ours, a
// configuration the stages reject is the caller's.
func TestRunFailureStatusFollowsTheCause(t *testing.T) {
	transient := &fakeRunner{err: fmt.Errorf("%w: every resolver failed the health check", app.ErrRuntime)}
	if got := post(t, newTestServer(t, transient), "secret", `{"domain":"example.com"}`).Code; got != http.StatusInternalServerError {
		t.Errorf("transient failure: status = %d, want 500", got)
	}

	// A port expression is parsed by the scanner, so a typo in it surfaces
	// here rather than at request validation.
	caller := &fakeRunner{err: errors.New(`ports "http" contains "http", which is not a port number`)}
	rec := post(t, newTestServer(t, caller), "secret", `{"domain":"example.com","ports":"http"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("caller mistake: status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not a port number") {
		t.Errorf("body = %s, want the offending part named", rec.Body)
	}
}

// A partial report is data, not an error: it says so itself.
func TestReportIsReturnedAsJSON(t *testing.T) {
	s := newTestServer(t, &fakeRunner{})
	rec := post(t, s, "secret", `{"domain":"example.com","stages":"enum"}`)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var got report.Report
	if err := json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &got); err != nil {
		t.Fatalf("response is not a report: %v", err)
	}
	if got.Run.Domain != "example.com" || got.SchemaVersion != report.SchemaVersion {
		t.Errorf("report = %+v, want the run described", got.Run)
	}
}

// The margin is what buys the time to serialize a truncated report instead of
// being cut off by the platform.
func TestBudgetReservesTheOutputMargin(t *testing.T) {
	cfg := &config.Config{Timeout: 100 * time.Second, OutputMargin: 0.1}
	if got := budget(cfg); got != 90*time.Second {
		t.Errorf("budget = %s, want 90s", got)
	}
	// A margin that would leave nothing must not produce a dead context.
	if got := budget(&config.Config{Timeout: time.Second, OutputMargin: 1}); got <= 0 {
		t.Errorf("budget = %s, want a positive window", got)
	}
}
