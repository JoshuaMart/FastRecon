package enumerate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
	"github.com/JoshuaMart/FastRecon/internal/version"
)

// maxTargetListBytes caps a fetched list. Unlike the resolver list this is a
// hard limit, not a truncation: a silently shortened target list turns hosts
// that were never queried into hosts that did not answer.
const maxTargetListBytes = 32 << 20

// TargetOptions describes where the host list comes from. Sources are merged.
type TargetOptions struct {
	Inline   []string
	File     string
	URL      string
	Headers  []string
	Timeout  time.Duration
	Redactor *secrets.Redactor
	Logger   *slog.Logger
}

// LoadTargets assembles the host list.
func LoadTargets(ctx context.Context, opts TargetOptions) ([]string, error) {
	if opts.Redactor == nil {
		opts.Redactor = secrets.NewRedactor(nil)
	}

	var (
		raw  []string
		errs []error
	)
	raw = append(raw, opts.Inline...)

	if opts.File != "" {
		lines, err := readTargetFile(opts.File)
		if err != nil {
			errs = append(errs, err)
		}
		raw = append(raw, lines...)
		opts.Logger.Debug("targets loaded", "source", opts.File, "count", len(lines))
	}
	if opts.URL != "" {
		lines, err := fetchTargetList(ctx, opts)
		if err != nil {
			errs = append(errs, errors.New(opts.Redactor.RedactError(err)))
		}
		raw = append(raw, lines...)
		opts.Logger.Debug("targets loaded", "source", opts.Redactor.Redact(opts.URL), "count", len(lines))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	hosts, malformed := parseTargets(raw)
	// Named and fatal, not skipped: a host dropped for a formatting reason is
	// a host that is never queried, and nothing downstream would say so.
	if len(malformed) > 0 {
		return nil, fmt.Errorf("targets: %d unusable entr%s: %s",
			len(malformed), plural(len(malformed)), strings.Join(sample(malformed, 5), ", "))
	}
	if len(hosts) == 0 {
		return nil, errors.New("targets: the list is empty")
	}
	return hosts, nil
}

func readTargetFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	defer func() { _ = f.Close() }()

	out, err := scanLines(f)
	if err != nil {
		return nil, fmt.Errorf("read targets file %s: %w", path, err)
	}
	return out, nil
}

// fetchTargetList downloads a host list, for deployments with no volume.
func fetchTargetList(ctx context.Context, opts TargetOptions) ([]string, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("targets url %q: %w", opts.URL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("targets url %q must use https", opts.URL)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, opts.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("targets url: %w", err)
	}
	req.Header.Set("User-Agent", version.UserAgent())
	for _, h := range opts.Headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return nil, fmt.Errorf("targets header %q must be in 'Name: value' form", h)
		}
		req.Header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch targets: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch targets: unexpected status %s", resp.Status)
	}

	// One byte past the cap, so an oversized list is detected rather than cut.
	limited := io.LimitReader(resp.Body, maxTargetListBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("fetch targets: %w", err)
	}
	if len(data) > maxTargetListBytes {
		return nil, fmt.Errorf("fetch targets: list exceeds %d bytes; refusing to scan a truncated list", maxTargetListBytes)
	}
	return scanLines(strings.NewReader(string(data)))
}

func scanLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// parseTargets normalizes and deduplicates hosts, returning what it could not
// make sense of.
func parseTargets(raw []string) (hosts, malformed []string) {
	seen := make(map[string]struct{}, len(raw))
	for _, entry := range raw {
		host, ok := normalizeTarget(entry)
		if !ok {
			malformed = append(malformed, entry)
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, malformed
}

// normalizeTarget applies the enumeration normalization without the root
// filter: a supplied host is in scope by definition, and a verification list
// legitimately spans several apexes of one perimeter.
func normalizeTarget(value string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(value))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "*.")
	if h == "" || strings.ContainsAny(h, " \t/@") || strings.Contains(h, "..") {
		return "", false
	}
	// A port would make the run-level port selection ambiguous.
	if strings.Contains(h, ":") {
		return "", false
	}
	if !strings.Contains(h, ".") {
		return "", false
	}
	if hasNonASCII(h) {
		ascii, err := idna.ToASCII(h)
		if err != nil {
			return "", false
		}
		h = ascii
	}
	return h, true
}

// List is an Enumerator over a fixed host list. It replaces stage 1 rather
// than skipping it, so exclusions still run on its output.
type List struct {
	hosts []string
	log   *slog.Logger
}

// NewList builds the static enumerator.
func NewList(hosts []string, log *slog.Logger) (*List, error) {
	if log == nil {
		return nil, errors.New("targets: logger is required")
	}
	if len(hosts) == 0 {
		return nil, errors.New("targets: the list is empty")
	}
	return &List{hosts: hosts, log: log}, nil
}

// Name identifies the stage implementation.
func (l *List) Name() string { return "targets" }

// Enumerate returns the supplied hosts. No source is queried.
func (l *List) Enumerate(context.Context, string) (pipeline.Enumeration, error) {
	l.log.Info("targets supplied", "count", len(l.hosts))
	return pipeline.Enumeration{Hosts: l.hosts, Sources: []report.Source{}}, nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func sample(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string{}, in[:n]...), "…")
}
