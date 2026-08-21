// Package enumerate collects subdomains from passive sources using subfaster (uses upstream provider-config format).
// (Only passive agent used; CLI config lookup skipped for container compatibility)
package enumerate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/passive"
	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"golang.org/x/net/idna"

	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
)

// defaultMaxEnumeration bounds an enumeration whose context has no deadline.
const defaultMaxEnumeration = 10 * time.Minute

// Options configures the enumerator.
type Options struct {
	// Sources to query. Ignored when All is set.
	Sources []string
	// ExcludeSources are removed from the selection.
	ExcludeSources []string
	// All queries every source the engine knows, not just the selection.
	All bool
	// SourceTimeout bounds a single source's HTTP session.
	SourceTimeout time.Duration
	Proxy         string
	Credentials   map[string]secrets.Credential
	Redactor      *secrets.Redactor
	Logger        *slog.Logger
}

// Subfaster is the subfaster-backed Enumerator.
type Subfaster struct {
	opts Options
}

var loggerOnce sync.Once

// NewSubfaster validates the source selection and prepares the engine.
func NewSubfaster(opts Options) (*Subfaster, error) {
	if opts.Logger == nil {
		return nil, errors.New("enumerate: logger is required")
	}
	if opts.Redactor == nil {
		opts.Redactor = secrets.NewRedactor(nil)
	}
	if opts.SourceTimeout <= 0 {
		return nil, errors.New("enumerate: source timeout must be positive")
	}

	// Engine's source lookup is case-sensitive and exits on empty set; normalize here to prevent crashes.
	opts.Sources = lowerAll(opts.Sources)
	opts.ExcludeSources = lowerAll(opts.ExcludeSources)

	if err := validateSources(append(append([]string{}, opts.Sources...), opts.ExcludeSources...)); err != nil {
		return nil, err
	}
	// Validate selection here (engine calls os.Exit on empty, so catch early).
	if !opts.All && len(effective(opts.Sources, opts.ExcludeSources)) == 0 {
		return nil, errors.New("enumerate: no sources selected; every source is excluded")
	}

	// Credentials exported by caller once (process-global; per-call export would cause conflicts).

	loggerOnce.Do(func() {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
		gologger.DefaultLogger.SetWriter(bridge{log: opts.Logger})
	})

	return &Subfaster{opts: opts}, nil
}

// Name identifies the stage implementation.
func (s *Subfaster) Name() string { return "subfaster" }

// Enumerate queries sources concurrently and returns deduplicated, in-scope results.
// (Failed/slow sources recorded but don't stop enumeration)
func (s *Subfaster) Enumerate(ctx context.Context, domain string) (pipeline.Enumeration, error) {
	agent := passive.New(s.sourceNames(), s.opts.ExcludeSources, s.opts.All, false)

	budget := enumerationBudget(ctx)
	s.opts.Logger.Debug("enumeration started",
		"sources", s.sourceNames(),
		"all_sources", s.opts.All,
		"budget", budget.String(),
		"source_timeout", s.opts.SourceTimeout.String(),
	)

	results := agent.EnumerateSubdomainsWithCtx(ctx, domain, s.opts.Proxy, int(s.opts.SourceTimeout.Seconds()), budget)

	var (
		hosts        []string
		seen         = map[string]struct{}{}
		errsBySource = map[string][]string{}
		outOfScope   int
	)

	for res := range results {
		switch res.Type {
		case subscraping.Error:
			if res.Error != nil {
				errsBySource[res.Source] = append(errsBySource[res.Source], s.opts.Redactor.RedactError(res.Error))
			}
		case subscraping.Subdomain:
			host, ok := normalize(res.Value, domain)
			if !ok {
				outOfScope++
				continue
			}
			if _, dup := seen[host]; dup {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)

	timedOut := ctx.Err() != nil
	out := pipeline.Enumeration{
		Hosts:   hosts,
		Sources: s.sourceStatuses(agent.GetStatistics(), errsBySource, timedOut),
	}
	out.Truncated = timedOut
	if outOfScope > 0 {
		s.opts.Logger.Debug("results dropped", "reason", "out of scope or malformed", "count", outOfScope)
	}
	for _, src := range out.Sources {
		if src.Status == report.SourceError || src.Status == report.SourceRateLimited {
			out.Warnings = append(out.Warnings, fmt.Sprintf("source %s: %s", src.Name, src.Error))
		}
	}
	return out, nil
}

// sourceStatuses converts per-source counters to report entries (all sources listed, even silent ones).
func (s *Subfaster) sourceStatuses(stats map[string]subscraping.Statistics, errs map[string][]string, timedOut bool) []report.Source {
	names := s.reportedSources(stats)
	out := make([]report.Source, 0, len(names))

	for _, name := range names {
		st := stats[name]
		entry := report.Source{
			Name:     name,
			Found:    st.Results,
			Duration: st.TimeTaken.Milliseconds(),
		}
		if msgs := errs[name]; len(msgs) > 0 {
			entry.Error = strings.Join(dedupe(msgs), "; ")
		}

		switch {
		case st.Skipped:
			entry.Status = report.SourceSkipped
			if s.needsKey(name) && !s.hasKey(name) {
				entry.Status = report.SourceSkippedNoKey
				entry.Error = ""
			}
		case rateLimited(entry.Error):
			entry.Status = report.SourceRateLimited
			entry.Partial = st.Results > 0
		case st.Errors > 0 && st.Results == 0:
			entry.Status = report.SourceError
		case st.Errors > 0:
			entry.Status = report.SourceOK
			entry.Partial = true
		case st.Results == 0 && timedOut:
			entry.Status = report.SourceTimeout
		default:
			entry.Status = report.SourceOK
		}
		out = append(out, entry)
	}
	return out
}

// reportedSources lists every source that should appear in the report: those
// the engine ran, plus any selected source it never reached.
func (s *Subfaster) reportedSources(stats map[string]subscraping.Statistics) []string {
	set := map[string]struct{}{}
	for name := range stats {
		set[name] = struct{}{}
	}
	if !s.opts.All {
		for _, name := range effective(s.opts.Sources, s.opts.ExcludeSources) {
			set[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *Subfaster) sourceNames() []string {
	if s.opts.All {
		return nil
	}
	return s.opts.Sources
}

// needsKey reports whether a source can use a credential at all. Optional-key
// sources count: they mark themselves skipped precisely when no key is
// configured, so "skipped_no_key" is the accurate reason for them too.
func (s *Subfaster) needsKey(name string) bool {
	src, ok := passive.NameSourceMap[name]
	if !ok {
		return false
	}
	req := src.KeyRequirement()
	return req == subscraping.RequiredKey || req == subscraping.OptionalKey
}

func (s *Subfaster) hasKey(name string) bool {
	_, ok := s.opts.Credentials[name]
	return ok
}

// enumerationBudget derives the engine's overall time limit from the stage
// deadline the pipeline handed down.
func enumerationBudget(ctx context.Context) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return defaultMaxEnumeration
	}
	if d := time.Until(dl); d > 0 {
		return d
	}
	// Already out of time: let the engine close immediately rather than
	// starting requests that cannot finish.
	return time.Millisecond
}

// normalize lowercases a result, strips the trailing dot and a wildcard
// label, and rejects anything outside the target domain.
func normalize(value, domain string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(value))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "*.")
	if h == "" || strings.ContainsAny(h, " \t/:@") || strings.Contains(h, "..") {
		return "", false
	}
	// Only convert when there is something to convert: the IDNA lookup
	// profile rejects underscores, which are legitimate in names like
	// _dmarc.example.com.
	if hasNonASCII(h) {
		ascii, err := idna.ToASCII(h)
		if err != nil {
			return "", false
		}
		h = ascii
	}
	if h == domain {
		return h, true
	}
	if !strings.HasSuffix(h, "."+domain) {
		return "", false
	}
	return h, true
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// rateLimited recognises the throttling responses sources use, so a run can
// tell a source that refused to answer from one that had nothing to say.
func rateLimited(msg string) bool {
	if msg == "" {
		return false
	}
	lower := strings.ToLower(msg)
	for _, marker := range []string{"429", "rate limit", "rate-limit", "ratelimit", "too many requests", "quota"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// effective returns the selection minus the exclusions.
func effective(sources, excluded []string) []string {
	drop := make(map[string]struct{}, len(excluded))
	for _, e := range excluded {
		drop[strings.ToLower(e)] = struct{}{}
	}
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		s = strings.ToLower(s)
		if _, ok := drop[s]; ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

// lowerAll normalizes source names, dropping the empties.
func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func validateSources(names []string) error {
	var unknown []string
	for _, n := range names {
		if _, ok := passive.NameSourceMap[strings.ToLower(n)]; !ok {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("unknown source(s): %s (run `fastrecon sources` for the list)", strings.Join(unknown, ", "))
}

// Available lists every source the engine knows, with its key requirement.
func Available() []SourceInfo {
	out := make([]SourceInfo, 0, len(passive.NameSourceMap))
	for name, src := range passive.NameSourceMap {
		info := SourceInfo{Name: name, Default: src.IsDefault()}
		switch src.KeyRequirement() {
		case subscraping.RequiredKey:
			info.Key = "required"
		case subscraping.OptionalKey:
			info.Key = "optional"
		default:
			info.Key = "none"
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SourceInfo describes an available source.
type SourceInfo struct {
	Name    string
	Key     string
	Default bool
}

// bridge routes the engine's own logging into the structured logger on
// stderr. stdout carries the report and must stay parseable, and unstructured
// lines interleaved with JSON logs are unreadable in a log-only environment.
type bridge struct{ log *slog.Logger }

func (b bridge) Write(data []byte, level levels.Level) {
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		return
	}
	// A source-level error is not a run failure, so it never rises above a
	// warning here; the report's per-source status is the real signal.
	if level == levels.LevelFatal || level == levels.LevelError {
		b.log.Warn("enumeration engine", "level", level.String(), "msg", msg)
		return
	}
	b.log.Debug("enumeration engine", "level", level.String(), "msg", msg)
}
