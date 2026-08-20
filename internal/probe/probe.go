// Package probe identifies the HTTP services behind the open ports.
//
// The client is httpx's, used at the request level rather than through its
// CLI runner: the runner calls gologger.Fatal — and therefore os.Exit — on
// several ordinary paths, and its enumeration entry point takes no context,
// so a run could neither be cancelled nor survive a bad input.
package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/projectdiscovery/httpx/common/httpx"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/ratelimit"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/version"
)

// maxTitleLength keeps a pathological <title> from bloating the report.
const maxTitleLength = 300

// Options configures the prober.
type Options struct {
	Concurrency int
	// Rate caps probes per second. An HTTP request costs a target far more
	// than a TCP handshake, so the probe sweep is rate-limited like the scan.
	Rate            int
	Timeout         time.Duration
	Retries         int
	FollowRedirects bool
	MaxRedirects    int
	UserAgent       string
	Headers         []string
	Logger          *slog.Logger
}

// HTTPX is the httpx-backed Prober.
type HTTPX struct {
	opts   Options
	client *httpx.HTTPX
	// direct never follows redirects. It is the fallback for a service whose
	// redirect target is unreachable: following the chain would fail the
	// whole request and lose a response that is itself a finding.
	direct  *httpx.HTTPX
	tech    *wappalyzer.Wappalyze
	limiter *ratelimit.Limiter
	// probe is the single point where requests happen, so the scheme
	// selection and result mapping can be tested without a network.
	probe func(ctx context.Context, host string, port int) *report.HTTP
}

// New builds the prober.
func New(opts Options) (*HTTPX, error) {
	switch {
	case opts.Logger == nil:
		return nil, errors.New("probe: logger is required")
	case opts.Concurrency < 1:
		return nil, errors.New("probe: concurrency must be at least 1")
	case opts.Timeout <= 0:
		return nil, errors.New("probe: timeout must be positive")
	case opts.Retries < 0:
		return nil, errors.New("probe: retries must not be negative")
	}

	headers, err := parseHeaders(opts.Headers)
	if err != nil {
		return nil, fmt.Errorf("probe: %w", err)
	}

	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = version.UserAgent()
	}

	newClient := func(follow bool) (*httpx.HTTPX, error) {
		return httpx.New(&httpx.Options{
			Timeout:          opts.Timeout,
			RetryMax:         opts.Retries,
			FollowRedirects:  follow,
			MaxRedirects:     opts.MaxRedirects,
			DefaultUserAgent: userAgent,
			CustomHeaders:    headers,
			// The certificate is a finding of its own: its SANs routinely
			// name hosts the enumeration never saw.
			TLSGrab: true,
		})
	}

	client, err := newClient(opts.FollowRedirects)
	if err != nil {
		return nil, fmt.Errorf("probe: %w", err)
	}
	direct := client
	if opts.FollowRedirects {
		if direct, err = newClient(false); err != nil {
			return nil, fmt.Errorf("probe: %w", err)
		}
	}

	tech, err := wappalyzer.New()
	if err != nil {
		return nil, fmt.Errorf("probe: technology fingerprints: %w", err)
	}

	h := &HTTPX{opts: opts, client: client, direct: direct, tech: tech, limiter: ratelimit.New(opts.Rate)}
	h.probe = h.probeOne
	return h, nil
}

// Name identifies the stage implementation.
func (h *HTTPX) Name() string { return "httpx" }

// Probe checks every open port for an HTTP service.
//
// Only the ports the scan actually found are probed. Assuming 80 and 443
// would report services that were never observed and miss the ones on
// unusual ports, which is the entire reason the scan runs first.
func (h *HTTPX) Probe(ctx context.Context, hosts []report.Host) (pipeline.Probe, error) {
	out := pipeline.Probe{Hosts: hosts}

	targets := plan(hosts)
	if len(targets) == 0 {
		h.opts.Logger.Info("http probe skipped", "reason", "no open port to probe")
		return out, nil
	}

	h.opts.Logger.Debug("http probe started", "targets", len(targets), "concurrency", h.opts.Concurrency, "rate", h.opts.Rate)
	defer h.limiter.Stop()

	results := make([]*report.HTTP, len(targets))
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		unchecked int
	)
	skip := func() {
		mu.Lock()
		unchecked++
		mu.Unlock()
	}

	// A fixed pool over a stream of indexes, rather than a goroutine per
	// target: the worker count is what --probe-concurrency promises, and
	// nothing is allocated for work that may never start.
	queue := make(chan int)
	for range h.opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range queue {
				if ctx.Err() != nil || !h.limiter.Wait(ctx) {
					skip()
					continue
				}
				results[i] = h.probe(ctx, targets[i].host, targets[i].port)
			}
		}()
	}

	for i := range targets {
		select {
		case queue <- i:
		case <-ctx.Done():
			skip()
		}
	}
	close(queue)
	wg.Wait()

	out.Hosts = attach(hosts, targets, results)
	if unchecked > 0 {
		out.Truncated = true
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d of %d open ports were not probed before the stage deadline", unchecked, len(targets)))
	}
	return out, nil
}

// target is one open port to probe.
type target struct {
	hostIndex int
	portIndex int
	host      string
	port      int
}

// plan lists every open port found by the scan.
func plan(hosts []report.Host) []target {
	var out []target
	for hi, h := range hosts {
		for pi, p := range h.Ports {
			if p.State != "open" {
				continue
			}
			out = append(out, target{hostIndex: hi, portIndex: pi, host: h.Host, port: p.Port})
		}
	}
	return out
}

// attach writes the probe results back onto their ports.
func attach(hosts []report.Host, targets []target, results []*report.HTTP) []report.Host {
	out := make([]report.Host, len(hosts))
	copy(out, hosts)
	for i := range out {
		out[i].Ports = append([]report.Port(nil), hosts[i].Ports...)
	}
	for i, t := range targets {
		if results[i] == nil {
			continue
		}
		out[t.hostIndex].Ports[t.portIndex].HTTP = results[i]
	}
	return out
}

// probeOne tries a port over HTTPS, then over plain HTTP.
//
// HTTPS is always tried first, on every port, because the TLS handshake is
// the only reliable discriminator. Trying HTTP first would misclassify TLS
// ports: a plain request to an HTTPS port commonly returns a real HTTP 400
// ("The plain HTTP request was sent to HTTPS port"), which looks exactly like
// a working HTTP service. A handshake, by contrast, either succeeds or fails.
func (h *HTTPX) probeOne(ctx context.Context, host string, port int) *report.HTTP {
	for _, scheme := range []string{"https", "http"} {
		if ctx.Err() != nil {
			return nil
		}
		if svc := h.request(ctx, scheme, host, port); svc != nil {
			return svc
		}
	}
	return nil
}

func (h *HTTPX) request(ctx context.Context, scheme, host string, port int) *report.HTTP {
	target := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))

	resp, err := h.do(ctx, h.client, target)
	unfollowed := false
	if err != nil && h.opts.FollowRedirects {
		// The chain may have broken on a later hop — a redirect to a host
		// whose TLS handshake fails, say. The first hop still answered, and
		// a 301 from an open port is a finding worth keeping.
		if direct, directErr := h.do(ctx, h.direct, target); directErr == nil {
			resp, err, unfollowed = direct, nil, true
		}
	}
	if err != nil {
		h.opts.Logger.Debug("probe failed", "target", target, "error", err)
		return nil
	}

	svc := &report.HTTP{
		URL:                target,
		Scheme:             scheme,
		RedirectUnfollowed: unfollowed,
		StatusCode:         resp.StatusCode,
		ContentLength:      int64(resp.ContentLength),
		ResponseTime:       resp.Duration.Milliseconds(),
		Title:              truncate(httpx.ExtractTitle(resp), maxTitleLength),
		Server:             firstHeader(resp.Headers, "Server"),
		Tech:               h.fingerprint(resp),
		Redirects:          chain(resp),
	}
	// The certificate is only recorded for a connection that was itself TLS.
	// A plain-HTTP probe that followed a redirect to an HTTPS host would
	// otherwise attach that other endpoint's certificate to this port.
	if scheme == "https" {
		svc.TLS = certificate(resp)
	}
	if final := finalURL(resp); final != "" && final != target {
		svc.FinalURL = final
	}
	return svc
}

// do issues one request with the given client.
func (h *HTTPX) do(ctx context.Context, client *httpx.HTTPX, target string) (*httpx.Response, error) {
	req, err := client.NewRequestWithContext(ctx, http.MethodGet, target)
	if err != nil {
		return nil, err
	}
	return client.Do(req, httpx.UnsafeOptions{})
}

// fingerprint identifies the technologies behind a response.
func (h *HTTPX) fingerprint(resp *httpx.Response) []string {
	if h.tech == nil {
		return nil
	}
	found := h.tech.Fingerprint(resp.Headers, resp.Data)
	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// certificate extracts the parts of the TLS response worth reporting. SANs
// may name hosts the enumeration missed; they are recorded but, by design,
// not fed back into the pipeline.
func certificate(resp *httpx.Response) *report.TLS {
	if resp.TLSData == nil || resp.TLSData.CertificateResponse == nil {
		return nil
	}
	cert := resp.TLSData.CertificateResponse
	out := &report.TLS{
		SubjectCN: cert.SubjectCN,
		Issuer:    cert.IssuerCN,
		NotAfter:  cert.NotAfter,
		SANs:      cert.SubjectAN,
	}
	if out.SubjectCN == "" && out.Issuer == "" && len(out.SANs) == 0 {
		return nil
	}
	return out
}

// chain lists the URLs a redirect walked through, so a service that ends
// somewhere unexpected can be traced back.
func chain(resp *httpx.Response) []string {
	if len(resp.Chain) == 0 {
		return nil
	}
	out := make([]string, 0, len(resp.Chain))
	for _, item := range resp.Chain {
		if item.RequestURL != "" {
			out = append(out, item.RequestURL)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// finalURL is where the redirects landed, which is the URL worth recording.
func finalURL(resp *httpx.Response) string {
	for i := len(resp.Chain) - 1; i >= 0; i-- {
		if url := resp.Chain[i].Location; url != "" {
			return url
		}
	}
	return ""
}

func firstHeader(headers map[string][]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func truncate(s string, limit int) string {
	s = strings.TrimSpace(s)
	if len(s) <= limit {
		return s
	}
	// Cutting at a byte offset can land inside a multi-byte rune, and the
	// JSON encoder then rewrites the broken tail to U+FFFD. Non-ASCII titles
	// are routine on real targets.
	for limit > 0 && !utf8.ValidString(s[:limit]) {
		limit--
	}
	return s[:limit] + "…"
}

// parseHeaders turns "Name: value" entries into the client's header map.
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
