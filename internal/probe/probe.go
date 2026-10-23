// Package probe identifies HTTP services behind open ports (httpx library, not CLI; CLI calls os.Exit).
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
	"github.com/projectdiscovery/utils/errkit"
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
	Concurrency     int
	Rate            int // HTTP probes are more expensive than TCP handshakes; rate-limited like port scan
	Timeout         time.Duration
	Retries         int
	FollowRedirects bool
	MaxRedirects    int
	UserAgent       string
	Headers         []string
	SPKI            bool // hash each HTTPS service's public key; costs one handshake
	Logger          *slog.Logger
}

// HTTPX is the httpx-backed Prober.
type HTTPX struct {
	opts   Options
	client *httpx.HTTPX
	direct *httpx.HTTPX // no redirects (fallback when a later hop breaks the chain); aliases client when redirects are off
	tech   *wappalyzer.Wappalyze
	probe  func(ctx context.Context, host string, port int) *report.HTTP // testable entry point
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

	h := &HTTPX{opts: opts, client: client, direct: direct, tech: tech}
	h.probe = h.probeOne
	return h, nil
}

// Name identifies the stage implementation.
func (h *HTTPX) Name() string { return "httpx" }

// Probe checks every open port for an HTTP service.
//
// Only the ports the scan found are probed; assuming 80 and 443 would report
// unobserved services and miss those on unusual ports.
func (h *HTTPX) Probe(ctx context.Context, hosts []report.Host) (pipeline.Probe, error) {
	out := pipeline.Probe{Hosts: hosts}

	targets := plan(hosts)
	if len(targets) == 0 {
		h.opts.Logger.Info("http probe skipped", "reason", "no open port to probe")
		return out, nil
	}

	h.opts.Logger.Debug("http probe started", "targets", len(targets), "concurrency", h.opts.Concurrency, "rate", h.opts.Rate)

	// The limiter belongs to the run, not the prober: a stopped limiter's Wait
	// returns immediately, so a reused instance would lose its rate limit.
	limiter := ratelimit.New(h.opts.Rate)
	defer limiter.Stop()

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

	// A fixed pool over a stream of indexes, not a goroutine per target: the
	// worker count is what --probe-concurrency promises.
	queue := make(chan int)
	for range h.opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range queue {
				if ctx.Err() != nil || !limiter.Wait(ctx) {
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
// HTTPS is tried first on every port because the TLS handshake is the only
// reliable discriminator: a plain request to an HTTPS port commonly returns a
// real HTTP 400 ("The plain HTTP request was sent to HTTPS port"), which looks
// like a working HTTP service. A handshake either succeeds or fails.
func (h *HTTPX) probeOne(ctx context.Context, host string, port int) *report.HTTP {
	for _, scheme := range []string{"https", "http"} {
		if ctx.Err() != nil {
			return nil
		}
		svc, err := h.request(ctx, scheme, host, port)
		if svc != nil {
			return svc
		}
		// Nothing accepted the connection; plain HTTP dials the same endpoint
		// and would be refused identically, so skip it (halves the wasted
		// budget on a wide sweep for ports closed since the scan).
		if dialFailed(err) {
			return nil
		}
	}
	return nil
}

// dialFailed reports whether the connection failed in a way that says
// something about the endpoint rather than the scheme: refused, unreachable,
// no such host. Retrying over plain HTTP would fail the same way.
//
// A timeout is deliberately not one: waiting is how a plain-HTTP server
// answers a TLS ClientHello, the case the second attempt exists for.
//
// The client replaces the transport error with its own type, losing the
// *net.OpError, so this asks the library rather than unwrapping. The
// *net.OpError branch still catches errors that bypassed the client.
func dialFailed(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	if errkit.GetErrorKind(err, errkit.ErrKindNetworkPermanent).Is(errkit.ErrKindNetworkPermanent) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func (h *HTTPX) request(ctx context.Context, scheme, host string, port int) (*report.HTTP, error) {
	// Connect to the explicit port, always; only the recorded URL is
	// canonical. Dropping the default port is not cosmetic: it leaves a
	// scheme on a non-default port (TLS answering on 80, say) as the only
	// kind that keeps its port, so the unusual case stands out.
	target := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	canonical := canonicalURL(scheme, host, port)

	// The first hop is requested on its own: it is the probed endpoint, so its
	// certificate is the one recorded, and an unresponsive port costs one
	// attempt rather than a followed request plus a fallback timeout.
	first, err := h.do(ctx, h.direct, target)
	if err != nil {
		h.opts.Logger.Debug("probe failed", "target", target, "error", err)
		return nil, err
	}
	resp, unfollowed := first, false
	if h.opts.FollowRedirects && isRedirect(first.StatusCode) {
		if followed, followErr := h.do(ctx, h.client, target); followErr == nil {
			resp = followed
		} else {
			// The chain broke on a later hop (a redirect to a host whose TLS
			// fails, say) but the first hop answered; that 301 is worth keeping.
			unfollowed = true
			h.opts.Logger.Debug("redirect not followed", "target", target, "error", followErr)
		}
	}

	svc := &report.HTTP{
		URL:                canonical,
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
	// The certificate is the probed endpoint's: from the first hop, and only
	// when that connection was TLS. A followed response carries the certificate
	// of wherever the chain ended, putting another host's names on this port.
	if scheme == "https" {
		svc.TLS = certificate(first)
		if h.opts.SPKI && svc.TLS != nil {
			svc.TLS.CertSPKIHash = h.spkiHash(ctx, host, port)
		}
	}
	if final := finalURL(resp); final != "" && final != target && final != canonical {
		svc.FinalURL = final
	}
	return svc, nil
}

// isRedirect reports whether a status asks the client to go elsewhere.
func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// do issues one request with the given client.
func (h *HTTPX) do(ctx context.Context, client *httpx.HTTPX, target string) (*httpx.Response, error) {
	req, err := client.NewRequestWithContext(ctx, http.MethodGet, target)
	if err != nil {
		return nil, err
	}
	return client.Do(req, httpx.UnsafeOptions{})
}

// canonicalURL omits the port when it is the scheme's default.
func canonicalURL(scheme, host string, port int) string {
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
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
	// Cutting at a byte offset can split a multi-byte rune, which the JSON
	// encoder rewrites to U+FFFD; non-ASCII titles are routine.
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
