package resolve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/version"
)

// DefaultResolvers: Cloudflare, Google, Quad9 (non-filtering, answer NXDOMAIN correctly).
// Filtering resolvers and NXDOMAIN redirects corrupt the live/dead split.
var DefaultResolvers = []string{
	"1.1.1.1:53", "1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", "8.8.4.4:53", // Google
	"9.9.9.10:53", "149.112.112.10:53", // Quad9, unfiltered endpoints
}

// maxResolverListBytes caps fetched lists (8MB; published lists are well under 1MB).
const maxResolverListBytes = 8 << 20

// LoadOptions specifies resolver list sources (merged together).
type LoadOptions struct {
	Inline  []string
	File    string
	URL     string
	Timeout time.Duration
	Logger  *slog.Logger
}

// LoadResolvers assembles the resolver list from all sources (falls back to bundled set).
func LoadResolvers(ctx context.Context, opts LoadOptions) ([]string, error) {
	if len(opts.Inline) == 0 && opts.File == "" && opts.URL == "" {
		return DefaultResolvers, nil
	}

	var (
		raw  []string
		errs []error
	)
	raw = append(raw, opts.Inline...)

	if opts.File != "" {
		fromFile, err := readResolverFile(opts.File)
		if err != nil {
			errs = append(errs, err)
		}
		raw = append(raw, fromFile...)
		opts.Logger.Debug("resolvers loaded", "source", opts.File, "count", len(fromFile))
	}

	if opts.URL != "" {
		fromURL, err := fetchResolverList(ctx, opts.URL, opts.Timeout)
		if err != nil {
			errs = append(errs, err)
		}
		raw = append(raw, fromURL...)
		opts.Logger.Debug("resolvers loaded", "source", opts.URL, "count", len(fromURL))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	resolvers, malformed := parseResolvers(raw)
	if len(malformed) > 0 {
		// Name them; silently dropping half a file hides errors.
		opts.Logger.Warn("resolver entries ignored",
			"count", len(malformed),
			"sample", malformed[:min(len(malformed), 5)],
		)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("resolve: no usable resolver in the configured sources")
	}
	return resolvers, nil
}

func readResolverFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read resolvers file: %w", err)
	}
	defer func() { _ = f.Close() }()

	out, err := scanResolvers(f)
	if err != nil {
		return nil, fmt.Errorf("read resolvers file %s: %w", path, err)
	}
	return out, nil
}

// fetchResolverList downloads a resolver list. This exists for the serverless
// deployments, which have no volume to mount a file from.
func fetchResolverList(ctx context.Context, raw string, timeout time.Duration) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("resolvers url %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		// The list decides where every DNS query goes; fetching it over a
		// channel anyone can rewrite would hand that decision away.
		return nil, fmt.Errorf("resolvers url %q must use https", raw)
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("resolvers url: %w", err)
	}
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch resolvers from %s: %w", raw, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch resolvers from %s: unexpected status %s", raw, resp.Status)
	}

	out, err := scanResolvers(io.LimitReader(resp.Body, maxResolverListBytes))
	if err != nil {
		return nil, fmt.Errorf("fetch resolvers from %s: %w", raw, err)
	}
	return out, nil
}

func scanResolvers(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	// Above the scanner's 64KB default: a published list that arrives with no
	// line separators is malformed, but it should say so rather than fail on
	// a token-length error.
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// parseResolvers normalizes and deduplicates entries, returning the ones it
// could not make sense of.
func parseResolvers(raw []string) (resolvers, malformed []string) {
	seen := make(map[string]struct{}, len(raw))
	for _, entry := range raw {
		addr, err := parseResolver(entry)
		if err != nil {
			malformed = append(malformed, entry)
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		resolvers = append(resolvers, addr)
	}
	return resolvers, malformed
}

// parseResolver accepts an IP with or without a port and returns host:port.
//
// Only literal addresses are accepted: a resolver given as a hostname would
// have to be resolved by some other resolver first, which is a dependency
// this stage should not have.
func parseResolver(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty resolver")
	}
	// Strip an inline comment, as published lists sometimes carry one.
	if i := strings.IndexAny(s, "#;"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}

	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(s, "53"), nil
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("resolver %q is not an IP address", raw)
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("resolver %q is not an IP address", raw)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("resolver %q has an invalid port", raw)
	}
	return net.JoinHostPort(host, port), nil
}
