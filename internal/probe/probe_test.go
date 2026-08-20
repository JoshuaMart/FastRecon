package probe

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/report"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(99)}))
}

func TestPlanCoversOnlyOpenPorts(t *testing.T) {
	hosts := []report.Host{
		{Host: "a.example.com", Status: report.StatusLive, Ports: []report.Port{
			{Port: 80, State: "open"},
			{Port: 22, State: "filtered"},
		}},
		{Host: "b.example.com", Status: report.StatusLive, Ports: []report.Port{{Port: 8443, State: "open"}}},
		{Host: "dead.example.com", Status: report.StatusDead},
	}

	got := plan(hosts)
	if len(got) != 2 {
		t.Fatalf("targets = %+v, want the two open ports", got)
	}
	if got[0].port != 80 || got[1].port != 8443 {
		t.Errorf("targets = %+v, want ports 80 and 8443", got)
	}
	// Assuming 80 and 443 is exactly what the scan exists to avoid.
	for _, tg := range got {
		if tg.port == 22 {
			t.Error("a non-open port was queued for probing")
		}
	}
}

func TestAttachWritesResultsOntoTheRightPort(t *testing.T) {
	hosts := []report.Host{
		{Host: "a.example.com", Ports: []report.Port{{Port: 80, State: "open"}, {Port: 8080, State: "open"}}},
		{Host: "b.example.com", Ports: []report.Port{{Port: 443, State: "open"}}},
	}
	targets := plan(hosts)
	results := []*report.HTTP{
		{URL: "http://a.example.com:80", Scheme: "http", StatusCode: http.StatusOK},
		nil, // 8080 answered nothing
		{URL: "https://b.example.com:443", Scheme: "https", StatusCode: http.StatusNoContent},
	}

	got := attach(hosts, targets, results)
	if got[0].Ports[0].HTTP == nil || got[0].Ports[0].HTTP.StatusCode != http.StatusOK {
		t.Errorf("port 80 = %+v, want the first result", got[0].Ports[0].HTTP)
	}
	if got[0].Ports[1].HTTP != nil {
		t.Error("port 8080 answered nothing and must stay bare")
	}
	if got[1].Ports[0].HTTP == nil || got[1].Ports[0].HTTP.Scheme != "https" {
		t.Errorf("port 443 = %+v, want the third result", got[1].Ports[0].HTTP)
	}
	// The input must not be mutated: the caller still holds it.
	if hosts[0].Ports[0].HTTP != nil {
		t.Error("attach mutated the hosts it was given")
	}
}

func newProber(t *testing.T, probe func(context.Context, string, int) *report.HTTP) *HTTPX {
	t.Helper()
	return &HTTPX{opts: Options{Concurrency: 4, Logger: discardLogger()}, probe: probe}
}

func TestProbeSkipsWhenNothingIsOpen(t *testing.T) {
	called := false
	h := newProber(t, func(context.Context, string, int) *report.HTTP {
		called = true
		return nil
	})

	res, err := h.Probe(context.Background(), []report.Host{{Host: "a.example.com", Status: report.StatusLive}})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("a probe was issued with no open port")
	}
	if len(res.Hosts) != 1 {
		t.Error("hosts must pass through untouched")
	}
}

func TestProbeReportsTruncationWhenOutOfTime(t *testing.T) {
	h := newProber(t, func(context.Context, string, int) *report.HTTP {
		return &report.HTTP{StatusCode: http.StatusOK}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := h.Probe(ctx, []report.Host{
		{Host: "a.example.com", Status: report.StatusLive, Ports: []report.Port{{Port: 80, State: "open"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("a probe stage cut short must report itself truncated")
	}
	if len(res.Warnings) == 0 {
		t.Error("a truncated probe must warn")
	}
}

func TestParseHeaders(t *testing.T) {
	got, err := parseHeaders([]string{"X-Trace: 1", "Accept: text/html,application/json"})
	if err != nil {
		t.Fatal(err)
	}
	if got["Accept"][0] != "text/html,application/json" {
		t.Errorf("headers = %v, a comma in the value was mangled", got)
	}
	for _, bad := range []string{"NoColon", ": empty-name", "Name:"} {
		if _, err := parseHeaders([]string{bad}); err == nil {
			t.Errorf("parseHeaders(%q) accepted a malformed header", bad)
		}
	}
}

func TestTruncateKeepsPathologicalTitlesOutOfTheReport(t *testing.T) {
	if got := truncate("  spaced  ", 100); got != "spaced" {
		t.Errorf("truncate = %q, want it trimmed", got)
	}
	long := strings.Repeat("x", maxTitleLength+50)
	got := truncate(long, maxTitleLength)
	if len([]rune(got)) != maxTitleLength+1 {
		t.Errorf("truncate produced %d runes, want the limit plus an ellipsis", len([]rune(got)))
	}
}

func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port
}

func newRealProber(t *testing.T, follow bool) *HTTPX {
	t.Helper()
	h, err := New(Options{
		Concurrency:     2,
		Timeout:         5 * time.Second,
		Retries:         0,
		FollowRedirects: follow,
		MaxRedirects:    3,
		Logger:          discardLogger(),
	})
	if err != nil {
		t.Skip("cannot build a prober here:", err)
	}
	return h
}

func TestProbeOneDetectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-server")
		_, _ = w.Write([]byte("<html><head><title>Plain</title></head></html>"))
	}))
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	got := newRealProber(t, true).probeOne(context.Background(), host, port)
	if got == nil {
		t.Fatal("no service found on a listening HTTP server")
	}
	if got.Scheme != "http" || got.StatusCode != http.StatusOK {
		t.Errorf("service = %+v, want http/200", got)
	}
	if got.Title != "Plain" {
		t.Errorf("title = %q, want Plain", got.Title)
	}
	if got.Server != "test-server" {
		t.Errorf("server = %q, want test-server", got.Server)
	}
	if got.TLS != nil {
		t.Error("a plain HTTP service must carry no certificate")
	}
}

// HTTPS is tried first on every port, so a TLS service on an unusual port is
// reported with the scheme that actually worked.
func TestProbeOneDetectsHTTPSOnAnUnusualPort(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<title>Secure</title>"))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	got := newRealProber(t, true).probeOne(context.Background(), host, port)
	if got == nil {
		t.Fatal("no service found on a listening HTTPS server")
	}
	if got.Scheme != "https" {
		t.Errorf("scheme = %q, want https", got.Scheme)
	}
	if got.URL != "https://"+host+":"+strconv.Itoa(port) {
		t.Errorf("url = %q, want it to match the probed scheme and port", got.URL)
	}
	if got.TLS == nil {
		t.Error("an HTTPS service must carry its certificate")
	}
}

// A plain request to an HTTPS port often returns a real HTTP 400, which looks
// exactly like a working HTTP service. Trying TLS first is what prevents that
// misclassification.
func TestHTTPSIsPreferredOverAPlainTextErrorOnTheSamePort(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<title>Secure</title>"))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	got := newRealProber(t, true).probeOne(context.Background(), host, port)
	if got == nil || got.Scheme != "https" {
		t.Fatalf("service = %+v, want the TLS scheme to win", got)
	}
}

// A service whose redirect target is unreachable still answered, and that
// answer is a finding.
func TestBrokenRedirectStillReportsTheFirstHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Port 1 is reserved and refuses instantly, so the chain cannot be
		// followed.
		http.Redirect(w, r, "http://127.0.0.1:1/gone", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	got := newRealProber(t, true).probeOne(context.Background(), host, port)
	if got == nil {
		t.Fatal("a service that redirects to a dead target was reported as absent")
	}
	if got.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want the 301 preserved", got.StatusCode)
	}
	if !got.RedirectUnfollowed {
		t.Error("a broken chain must be marked, not hidden")
	}
}

func TestProbeOneReturnsNothingOnAClosedPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	host, port := hostPort(t, srv.URL)
	srv.Close()

	if got := newRealProber(t, false).probeOne(context.Background(), host, port); got != nil {
		t.Errorf("service = %+v, want nothing on a closed port", got)
	}
}

func TestNewRejectsUnusableOptions(t *testing.T) {
	base := Options{Concurrency: 1, Timeout: time.Second, Logger: discardLogger()}
	for name, mutate := range map[string]func(*Options){
		"no logger":        func(o *Options) { o.Logger = nil },
		"no concurrency":   func(o *Options) { o.Concurrency = 0 },
		"no timeout":       func(o *Options) { o.Timeout = 0 },
		"negative retries": func(o *Options) { o.Retries = -1 },
		"bad header":       func(o *Options) { o.Headers = []string{"nope"} },
	} {
		opts := base
		mutate(&opts)
		if _, err := New(opts); err == nil {
			t.Errorf("New accepted options with %s", name)
		}
	}
}
