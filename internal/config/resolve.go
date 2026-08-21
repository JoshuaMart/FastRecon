package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/stage"
)

// Load resolves a configuration from parsed flags, the environment and an
// optional config file, then validates it.
func Load(fs *pflag.FlagSet) (*Config, error) {
	return resolveConfig(fs, true)
}

// LoadServe is Load for the HTTP handler, where the domain is not known at
// startup: it arrives with each request and is validated then, by the same
// rules.
func LoadServe(fs *pflag.FlagSet) (*Config, error) {
	return resolveConfig(fs, false)
}

func resolveConfig(fs *pflag.FlagSet, requireDomain bool) (*Config, error) {
	l := &loader{fs: fs}

	// The config file path itself can only come from a flag or the
	// environment — it cannot be defined by the file it selects.
	cfgPath := l.str("config")
	file, resolvedPath, err := loadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	l.file = file

	cfg := &Config{ConfigFile: resolvedPath}

	cfg.Domain = l.str("domain")
	cfg.Targets = l.strs("targets")
	cfg.TargetsFile = l.str("targets-file")
	cfg.TargetsURL = l.str("targets-url")
	cfg.TargetsHeader = l.strs("targets-header")
	cfg.Exclude = l.strs("exclude")
	cfg.ExcludeFile = l.str("exclude-file")
	cfg.ExcludeStrictWildcard = l.bool("exclude-strict-wildcard")
	cfg.ReportExcluded = l.bool("report-excluded")

	cfg.Timeout = l.dur("timeout")
	cfg.OutputMargin = l.f64("output-margin")

	cfg.ProviderConfig = l.str("provider-config")
	cfg.Sources = l.strs("sources")
	cfg.ExcludeSources = l.strs("exclude-sources")
	cfg.AllSources = l.bool("all-sources")
	cfg.SourceTimeout = l.dur("source-timeout")

	cfg.Resolvers = l.strs("resolvers")
	cfg.ResolversFile = l.str("resolvers-file")
	cfg.ResolversURL = l.str("resolvers-url")
	cfg.ValidateResolvers = l.bool("validate-resolvers")
	cfg.ResolverHealthBudget = l.dur("resolver-health-budget")
	cfg.ResolverConcurrency = l.int("resolver-concurrency")
	cfg.ResolverRetries = l.int("resolver-retries")
	cfg.ResolverTimeout = l.dur("resolver-timeout")
	cfg.WildcardProbes = l.int("wildcard-probes")

	cfg.ScanMode = l.str("scan-mode")
	cfg.Ports = l.str("ports")
	cfg.ExcludePorts = l.str("exclude-ports")
	cfg.SkipCDN = l.bool("skip-cdn")
	cfg.ScanConcurrency = l.int("scan-concurrency")
	cfg.ScanRate = l.int("scan-rate")
	cfg.ScanTimeout = l.dur("scan-timeout")
	cfg.ScanRetries = l.int("scan-retries")

	cfg.ProbeSPKI = l.bool("probe-spki")
	cfg.ProbeConcurrency = l.int("probe-concurrency")
	cfg.ProbeRate = l.int("probe-rate")
	cfg.ProbeTimeout = l.dur("probe-timeout")
	cfg.ProbeRetries = l.int("probe-retries")
	cfg.ProbeFollowRedirects = l.bool("probe-follow-redirects")
	cfg.ProbeMaxRedirects = l.int("probe-max-redirects")
	cfg.ProbeUserAgent = l.str("probe-user-agent")
	cfg.ProbeHeaders = l.strs("probe-header")

	cfg.Output = l.str("output")
	cfg.WebhookURL = l.str("webhook-url")
	cfg.WebhookMethod = l.str("webhook-method")
	cfg.WebhookHeaders = l.strs("webhook-header")
	cfg.WebhookTimeout = l.dur("webhook-timeout")
	cfg.WebhookRetries = l.int("webhook-retries")

	cfg.LogLevel = l.str("log-level")
	cfg.LogFormat = l.str("log-format")
	cfg.Environment = l.str("environment")
	cfg.Listen = l.str("listen")
	cfg.APIToken = l.str("api-token")

	// Values needing a parse step of their own.
	if scope, err := stage.ParseScope(l.str("stages")); err != nil {
		l.errs = append(l.errs, err)
	} else {
		cfg.Scope = scope
	}
	if format, err := report.ParseFormat(l.str("format")); err != nil {
		l.errs = append(l.errs, err)
	} else {
		cfg.Format = format
	}
	if err := errors.Join(l.errs...); err != nil {
		return nil, err
	}

	if err := cfg.mergeExcludeFile(); err != nil {
		return nil, err
	}
	l.warnUnknownKeys(cfg)

	if err := cfg.validate(requireDomain); err != nil {
		return nil, err
	}
	return cfg, nil
}

// maxLineBytes raises the line ceiling above the scanner's 64KB default. An
// exclusion regexp can be long, and a fetched list can arrive as one line with
// no separators at all; both would otherwise fail with an error that names
// neither the file nor the cause.
const maxLineBytes = 1 << 20

// mergeExcludeFile appends the patterns of --exclude-file to the inline ones.
// Parsing the patterns themselves belongs to the exclusion stage; here they
// are only collected.
func (c *Config) mergeExcludeFile() error {
	if c.ExcludeFile == "" {
		return nil
	}
	f, err := os.Open(c.ExcludeFile)
	if err != nil {
		return fmt.Errorf("read exclude file: %w", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(nil, maxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c.Exclude = append(c.Exclude, line)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read exclude file %s: %w", c.ExcludeFile, err)
	}
	return nil
}

// loader reads one option at a time, applying the documented precedence.
type loader struct {
	fs   *pflag.FlagSet
	file map[string]any
	errs []error
	// read records every key the loader looked up, so leftover file keys can
	// be reported as probable typos.
	read map[string]bool
}

func (l *loader) note(name string) {
	if l.read == nil {
		l.read = map[string]bool{}
	}
	l.read[name] = true
}

func (l *loader) errf(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

// raw returns the highest-precedence override for a flag, if any. A nil
// result means "no override": use the flag's own value, which is either the
// parsed flag or its default.
func (l *loader) raw(name string) *string {
	l.note(name)
	if l.fs.Changed(name) {
		return nil
	}
	if v, ok := lookupEnv(name); ok {
		return &v
	}
	if v, ok := l.file[name]; ok {
		s := fmt.Sprint(v)
		return &s
	}
	return nil
}

func (l *loader) str(name string) string {
	v, err := l.fs.GetString(name)
	if err != nil {
		l.errf("flag %s: %w", name, err)
		return ""
	}
	if o := l.raw(name); o != nil {
		return *o
	}
	return v
}

func (l *loader) bool(name string) bool {
	v, err := l.fs.GetBool(name)
	if err != nil {
		l.errf("flag %s: %w", name, err)
		return false
	}
	o := l.raw(name)
	if o == nil {
		return v
	}
	b, err := strconv.ParseBool(strings.TrimSpace(*o))
	if err != nil {
		l.errf("%s: %q is not a boolean", name, *o)
		return v
	}
	return b
}

func (l *loader) int(name string) int {
	v, err := l.fs.GetInt(name)
	if err != nil {
		l.errf("flag %s: %w", name, err)
		return 0
	}
	o := l.raw(name)
	if o == nil {
		return v
	}
	n, err := strconv.Atoi(strings.TrimSpace(*o))
	if err != nil {
		l.errf("%s: %q is not an integer", name, *o)
		return v
	}
	return n
}

func (l *loader) f64(name string) float64 {
	v, err := l.fs.GetFloat64(name)
	if err != nil {
		l.errf("flag %s: %w", name, err)
		return 0
	}
	o := l.raw(name)
	if o == nil {
		return v
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(*o), 64)
	if err != nil {
		l.errf("%s: %q is not a number", name, *o)
		return v
	}
	return f
}

func (l *loader) dur(name string) time.Duration {
	v, err := l.fs.GetDuration(name)
	if err != nil {
		l.errf("flag %s: %w", name, err)
		return 0
	}
	o := l.raw(name)
	if o == nil {
		return v
	}
	d, err := time.ParseDuration(strings.TrimSpace(*o))
	if err != nil {
		l.errf("%s: %q is not a duration (e.g. 30s, 10m)", name, *o)
		return v
	}
	return d
}

// strs resolves a repeatable flag. The environment form accepts newline
// separation always, and comma separation for options whose values cannot
// contain a comma. The file form accepts a list or a single scalar.
func (l *loader) strs(name string) []string {
	v, err := l.fs.GetStringArray(name)
	if err != nil {
		// The comma-splitting flags are registered as slices, not arrays.
		if v, err = l.fs.GetStringSlice(name); err != nil {
			l.errf("flag %s: %w", name, err)
			return nil
		}
	}
	l.note(name)
	if l.fs.Changed(name) {
		return v
	}
	if s, ok := lookupEnv(name); ok {
		return splitValue(name, s)
	}
	if raw, ok := l.file[name]; ok {
		switch t := raw.(type) {
		case []any:
			out := make([]string, 0, len(t))
			for _, item := range t {
				out = append(out, strings.TrimSpace(fmt.Sprint(item)))
			}
			return out
		case string:
			return splitValue(name, t)
		default:
			l.errf("%s: expected a list in the config file", name)
			return v
		}
	}
	return v
}

// splitValue applies the flag's separator rule to an environment or config
// value.
func splitValue(name, value string) []string {
	if patternFlags[name] {
		return splitPatterns(value)
	}
	return splitList(value, !newlineOnlyFlags[name])
}

// splitPatterns separates exclusion patterns.
//
// Lines are the outer separator. A line starting with "re:" is a single
// pattern, kept whole — a regexp may contain commas, and cutting one produces
// two halves that still compile, so the mistake would be silent. Any other
// line is a comma-separated list of hosts and wildcards, which is what makes
// the compact form usable in a job's environment variable.
func splitPatterns(value string) []string {
	var out []string
	for line := range strings.SplitSeq(value, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "re:") {
			out = append(out, line)
			continue
		}
		out = append(out, splitList(line, true)...)
	}
	return out
}

func splitList(s string, splitComma bool) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		if r == '\n' || r == '\r' {
			return true
		}
		return splitComma && r == ','
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// warnUnknownKeys flags config-file keys that match no option. A silently
// ignored key looks identical to a key that took effect, so it must be loud.
func (l *loader) warnUnknownKeys(cfg *Config) {
	for k := range l.file {
		if !l.read[k] {
			cfg.warnf("config file key %q matches no option and was ignored", k)
		}
	}
}
