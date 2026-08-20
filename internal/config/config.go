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
	Enumerator     string
	ProviderConfig string
	Sources        []string
	ExcludeSources []string
	AllSources     bool
	SourceTimeout  time.Duration

	// Resolution
	Resolvers            []string
	ResolversFile        string
	ResolversURL         string
	ValidateResolvers    bool
	ResolverHealthBudget time.Duration
	ResolverConcurrency  int
	ResolverRetries      int
	ResolverTimeout      time.Duration
	WildcardProbes       int

	// Port scan
	ScanMode        string
	Ports           string
	ExcludePorts    string
	SkipCDN         bool
	ScanConcurrency int
	ScanRate        int
	ScanTimeout     time.Duration
	ScanRetries     int

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

// RequiredSources is the default source selection: the sources a run is
// expected to use. The keyed ones report themselves as skipped when no
// credential is configured, rather than being silently dropped.
//
//	chaos           ProjectDiscovery Chaos   key required
//	securitytrails  SecurityTrails           key required
//	c99             c99.nl                   key required
//	submd           sub.md                   key optional
//	crt             crt.name                 key optional
var RequiredSources = []string{"chaos", "securitytrails", "c99", "submd", "crt"}

// Scan modes.
const (
	ScanModeConnect = "connect"
	ScanModeSYN     = "syn"
)

// StdoutPath is the Output value that selects the stdout sink.
const StdoutPath = "-"

// Sinks reports which destinations are configured.
func (c *Config) Sinks() (stdout, file, webhook bool) {
	return c.Output == StdoutPath, c.Output != "" && c.Output != StdoutPath, c.WebhookURL != ""
}

func (c *Config) warnf(format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, args...))
}
