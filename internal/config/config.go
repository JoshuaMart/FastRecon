// Package config resolves the run configuration.
//
// Every option is settable three ways and the precedence is always the same:
//
//	CLI flag > environment variable > config file > built-in default
//
// The names are mechanically related: a flag named "http-timeout" reads the
// environment variable FASTRECON_HTTP_TIMEOUT and the config-file key
// "http-timeout". That rule is what lets a serverless job be configured
// entirely through environment variables without a config file.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/stage"
)

// EnvPrefix is prepended to every derived environment-variable name.
const EnvPrefix = "FASTRECON_"

// Config is the fully resolved configuration of a single run.
type Config struct {
	// Target
	Domain                string
	Exclude               []string
	ExcludeFile           string
	ExcludeStrictWildcard bool
	ReportExcluded        bool

	// Pipeline
	Scope   stage.Scope
	Timeout time.Duration
	// OutputMargin is the fraction of the total budget reserved for building
	// and delivering the report, so a deadline yields a truncated report
	// instead of a killed process.
	OutputMargin float64

	// Enumeration
	Enumerator        string
	ProviderConfig    string
	SourceRetryBudget Allowance

	// Resolution
	Resolvers           []string
	ResolverConcurrency int
	ResolverRetries     int
	ResolverTimeout     time.Duration

	// Port scan
	ScanMode        string
	Ports           string
	ExcludePorts    string
	SkipCDN         bool
	ScanConcurrency int
	ScanRate        int
	ScanTimeout     time.Duration

	// HTTP probe
	ProbeConcurrency     int
	ProbeTimeout         time.Duration
	ProbeFollowRedirects bool
	ProbeMaxRedirects    int
	ProbeUserAgent       string
	ProbeHeaders         []string

	// Output
	Output         string
	Format         report.Format
	WebhookURL     string
	WebhookMethod  string
	WebhookHeaders []string
	WebhookTimeout time.Duration
	WebhookRetries int

	// Process
	LogLevel    string
	LogFormat   string
	Environment string
	ConfigFile  string

	// Serve mode
	Listen   string
	APIToken string

	// Warnings collected while resolving, surfaced in the report so a typo in
	// a config file is visible rather than silently ignored.
	Warnings []string
}

// Scan modes.
const (
	ScanModeConnect = "connect"
	ScanModeSYN     = "syn"
)

// StdoutPath is the Output value that selects the stdout sink.
const StdoutPath = "-"

// Allowance is a budget expressed either as a fraction of a larger budget
// ("25%") or as an absolute duration ("90s").
type Allowance struct {
	Percent  float64
	Duration time.Duration
}

// ParseAllowance reads "25%" or a Go duration.
func ParseAllowance(s string) (Allowance, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Allowance{}, fmt.Errorf("empty allowance")
	}
	if pct, ok := strings.CutSuffix(s, "%"); ok {
		v, err := strconv.ParseFloat(strings.TrimSpace(pct), 64)
		if err != nil {
			return Allowance{}, fmt.Errorf("invalid percentage %q", s)
		}
		if v <= 0 || v > 100 {
			return Allowance{}, fmt.Errorf("percentage %q out of range (0, 100]", s)
		}
		return Allowance{Percent: v / 100}, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return Allowance{}, fmt.Errorf("invalid allowance %q: want a percentage or a duration", s)
	}
	if d <= 0 {
		return Allowance{}, fmt.Errorf("allowance %q must be positive", s)
	}
	return Allowance{Duration: d}, nil
}

// Of resolves the allowance against a total budget.
func (a Allowance) Of(total time.Duration) time.Duration {
	if a.Duration > 0 {
		return min(a.Duration, total)
	}
	return time.Duration(float64(total) * a.Percent)
}

func (a Allowance) String() string {
	if a.Duration > 0 {
		return a.Duration.String()
	}
	return strconv.FormatFloat(a.Percent*100, 'f', -1, 64) + "%"
}

// Sinks reports which destinations are configured.
func (c *Config) Sinks() (stdout, file, webhook bool) {
	return c.Output == StdoutPath, c.Output != "" && c.Output != StdoutPath, c.WebhookURL != ""
}

func (c *Config) warnf(format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, args...))
}
