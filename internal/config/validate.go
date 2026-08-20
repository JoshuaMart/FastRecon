package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Validate normalizes the configuration and reports every problem at once,
// rather than one per run.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	domain, err := NormalizeDomain(c.Domain)
	if err != nil {
		fail("%w", err)
	}
	c.Domain = domain

	if c.Timeout <= 0 {
		fail("timeout must be positive, got %s", c.Timeout)
	}
	if c.OutputMargin < 0 || c.OutputMargin >= 0.5 {
		fail("output-margin must be in [0, 0.5), got %v", c.OutputMargin)
	}

	switch c.ScanMode {
	case ScanModeConnect, ScanModeSYN:
	default:
		fail("unknown scan-mode %q (valid: %s, %s)", c.ScanMode, ScanModeConnect, ScanModeSYN)
	}
	if c.Ports == "" {
		fail("ports must not be empty")
	}

	// Source names are matched case-sensitively by the engine, so they are
	// normalized here, once, rather than at each of the several places that
	// look them up.
	c.Sources = lowerAll(c.Sources)
	c.ExcludeSources = lowerAll(c.ExcludeSources)
	if !c.AllSources && len(c.Sources) == 0 {
		fail("no enumeration source selected: set --sources or --all-sources")
	}

	// The enumeration engine takes its per-source ceiling in whole seconds,
	// and truncates: anything under a second silently becomes no ceiling at
	// all, letting one hung source consume the entire stage budget.
	if c.SourceTimeout > 0 && c.SourceTimeout < time.Second {
		fail("source-timeout must be at least 1s, got %s: the engine takes whole seconds and would round it to no timeout", c.SourceTimeout)
	}

	for _, p := range []struct {
		name string
		v    int
	}{
		{"resolver-concurrency", c.ResolverConcurrency},
		{"wildcard-probes", c.WildcardProbes},
		{"scan-concurrency", c.ScanConcurrency},
		{"probe-concurrency", c.ProbeConcurrency},
		{"probe-rate", c.ProbeRate},
	} {
		if p.v < 1 {
			fail("%s must be at least 1, got %d", p.name, p.v)
		}
	}
	for _, p := range []struct {
		name string
		v    int
	}{
		{"resolver-retries", c.ResolverRetries},
		{"probe-max-redirects", c.ProbeMaxRedirects},
		{"probe-retries", c.ProbeRetries},
		{"webhook-retries", c.WebhookRetries},
		{"scan-rate", c.ScanRate},
		{"scan-retries", c.ScanRetries},
	} {
		if p.v < 0 {
			fail("%s must not be negative, got %d", p.name, p.v)
		}
	}
	for _, p := range []struct {
		name string
		v    time.Duration
	}{
		{"source-timeout", c.SourceTimeout},
		{"resolver-timeout", c.ResolverTimeout},
		{"resolver-health-budget", c.ResolverHealthBudget},
		{"scan-timeout", c.ScanTimeout},
		{"probe-timeout", c.ProbeTimeout},
		{"webhook-timeout", c.WebhookTimeout},
	} {
		if p.v <= 0 {
			fail("%s must be positive, got %s", p.name, p.v)
		}
	}

	if err := validateHeaders("probe-header", c.ProbeHeaders); err != nil {
		errs = append(errs, err)
	}

	if c.WebhookURL != "" {
		if err := validateWebhookURL(c.WebhookURL); err != nil {
			errs = append(errs, err)
		}
		if err := validateHeaders("webhook-header", c.WebhookHeaders); err != nil {
			errs = append(errs, err)
		}
		c.WebhookMethod = strings.ToUpper(strings.TrimSpace(c.WebhookMethod))
		switch c.WebhookMethod {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
		default:
			fail("webhook-method %q is not a method that carries a body (valid: POST, PUT, PATCH)", c.WebhookMethod)
		}
	} else if len(c.WebhookHeaders) > 0 {
		fail("webhook-header set without webhook-url")
	}

	if c.Output != StdoutPath && c.Output != "" {
		if info, err := os.Stat(c.Output); err == nil && info.IsDir() {
			fail("output %q is a directory, expected a file path", c.Output)
		}
	}
	if c.Output == "" && c.WebhookURL == "" {
		fail("no destination configured: set --output or --webhook-url")
	}

	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		fail("unknown log-level %q (valid: debug, info, warn, error)", c.LogLevel)
	}
	switch strings.ToLower(c.LogFormat) {
	case "json", "text":
	default:
		fail("unknown log-format %q (valid: json, text)", c.LogFormat)
	}

	// stdout carries the report; sending logs there too would corrupt it.
	if c.Output == StdoutPath && c.Format == "" {
		fail("format must be set when writing to stdout")
	}

	if c.ResolversFile != "" {
		if _, err := os.Stat(c.ResolversFile); err != nil {
			fail("resolvers-file %q is not readable: %v", c.ResolversFile, err)
		}
	}

	if c.ProviderConfig != "" {
		if _, err := os.Stat(c.ProviderConfig); err != nil {
			fail("provider-config %q is not readable: %v", c.ProviderConfig, err)
		}
	}

	return errors.Join(errs...)
}

// NormalizeDomain lowercases a root domain and rejects anything that is not
// one: a URL, a path, a wildcard, a single label.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSpace(strings.ToLower(d))
	if d == "" {
		return "", errors.New("domain is required (-d/--domain or FASTRECON_DOMAIN)")
	}
	if strings.Contains(d, "://") || strings.ContainsAny(d, "/ \t") {
		return "", fmt.Errorf("domain %q must be a bare domain, not a URL", d)
	}
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if !domainRE.MatchString(d) {
		if hasNonASCII(d) {
			return "", fmt.Errorf("domain %q must be ASCII; pass the punycode form (xn--...)", d)
		}
		return "", fmt.Errorf("domain %q is not a valid domain name", d)
	}
	return d, nil
}

// lowerAll normalizes a list of names, dropping the empties.
func lowerAll(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("webhook-url %q is not a URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook-url %q must use http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook-url %q has no host", raw)
	}
	return nil
}

func validateHeaders(flag string, headers []string) error {
	var errs []error
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s %q must be in 'Name: value' form", flag, h))
		}
	}
	return errors.Join(errs...)
}
