package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/JoshuaMart/FastRecon/internal/stage"
)

// newlineOnlyFlags hold values that may legitimately contain a comma, so
// their environment form is split on newlines only.
var newlineOnlyFlags = map[string]bool{
	"probe-header":   true,
	"webhook-header": true,
}

// patternFlags hold exclusion patterns, which need a rule of their own: a
// regexp's repeat count contains a comma, and splitting on it yields two
// halves that both still compile — so the run would quietly scan hosts the
// operator excluded. See splitPatterns.
var patternFlags = map[string]bool{"exclude": true}

// RegisterFlags defines the full option surface. Defaults live here and
// nowhere else, so `--help` is the reference for what a run does by default.
func RegisterFlags(fs *pflag.FlagSet) {
	fs.StringP("domain", "d", "", "root domain to enumerate (required)")
	fs.StringArray("exclude", nil, "exclusion pattern: host, *.suffix, or re:<regexp> (repeatable)")
	fs.String("exclude-file", "", "file of exclusion patterns, one per line, # for comments")
	fs.Bool("exclude-strict-wildcard", false, "*.x.example.com excludes hosts under x.example.com but not x.example.com itself")
	fs.Bool("report-excluded", false, "list excluded hosts and the pattern that matched in the report")

	fs.String("stages", string(stage.ScopeFull), fmt.Sprintf("pipeline scope: %s", scopeList()))
	fs.Duration("timeout", 30*time.Minute, "global deadline for the whole run")
	fs.Float64("output-margin", 0.10, "fraction of the deadline reserved to build and deliver the report")

	fs.String("provider-config", "", "path to the source credentials file (never baked into the image)")
	fs.StringArray("sources", RequiredSources, "enumeration sources to query (repeatable); see `fastrecon sources`")
	fs.StringArray("exclude-sources", nil, "sources to remove from the selection (repeatable)")
	fs.Bool("all-sources", false, "query every source the engine knows, not just the selection")
	fs.Duration("source-timeout", 30*time.Second, "time ceiling for a single source, retries and backoff included; whole seconds only")

	fs.StringArray("resolvers", nil, "DNS resolver IP to use (repeatable); empty uses the bundled set")
	fs.String("resolvers-file", "", "file of resolver IPs, one per line, # for comments")
	fs.String("resolvers-url", "", "https URL of a resolver list, fetched at startup (30s ceiling); for deployments with no volume to mount")
	fs.Bool("validate-resolvers", true, "drop resolvers that are unreachable, answer a known name wrongly, or hijack NXDOMAIN")
	fs.Duration("resolver-health-budget", 30*time.Second, "ceiling on the resolver health check; resolvers not reached in time are kept and counted")
	fs.Int("resolver-concurrency", 100, "concurrent DNS queries")
	fs.Int("resolver-retries", 2, "extra attempts per DNS query after the first")
	fs.Duration("resolver-timeout", 5*time.Second, "timeout per DNS query")
	fs.Int("wildcard-probes", 3, "random names resolved per parent domain to detect a wildcard record")

	fs.String("scan-mode", ScanModeConnect, fmt.Sprintf("port scan mode: %s (unprivileged) or %s (needs CAP_NET_RAW)", ScanModeConnect, ScanModeSYN))
	fs.String("ports", "top-100", "ports to scan: top-100, top-1000, web, or a list like 80,443,8000-8100")
	fs.String("exclude-ports", "", "ports to subtract from the selection")
	fs.Bool("skip-cdn", true, "on CDN/WAF addresses, scan only the standard web ports; detection runs and is reported either way")
	fs.Int("scan-concurrency", 200, "concurrent port connections")
	fs.Int("scan-rate", 1000, "port scan packets per second")
	fs.Duration("scan-timeout", 3*time.Second, "timeout per port connection")
	fs.Int("scan-retries", 2, "retries per port")

	fs.Int("probe-concurrency", 50, "concurrent HTTP probes")
	fs.Int("probe-rate", 200, "HTTP probes per second")
	fs.Duration("probe-timeout", 10*time.Second, "timeout per HTTP probe")
	fs.Int("probe-retries", 1, "retries per HTTP probe")
	fs.Bool("probe-follow-redirects", false, "follow redirects while probing; the Location target is recorded either way")
	fs.Int("probe-max-redirects", 5, "maximum redirect hops")
	fs.String("probe-user-agent", "", "User-Agent sent while probing; empty uses the built-in one")
	fs.StringArray("probe-header", nil, "extra header sent while probing, as 'Name: value' (repeatable)")

	fs.StringP("output", "o", StdoutPath, "report destination: a file path, or - for stdout")
	fs.String("format", "json", "report format: json, jsonl, text")
	fs.String("webhook-url", "", "POST the report as raw JSON to this URL")
	fs.String("webhook-method", "POST", "HTTP method for the webhook")
	fs.StringArray("webhook-header", nil, "extra header for the webhook, as 'Name: value' (repeatable)")
	fs.Duration("webhook-timeout", 30*time.Second, "timeout per webhook attempt")
	fs.Int("webhook-retries", 3, "webhook retries on 5xx, 429 and transport errors")

	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")
	fs.String("log-format", "json", "log format on stderr: json, text")
	fs.String("environment", "", "environment label recorded in the report; empty auto-detects")
	fs.String("config", "", "config file path, or 'auto' to look in the user config directory")

	fs.String("listen", ":8080", "serve mode: address to bind")
	fs.String("api-token", "", "serve mode: shared token required on every request")
}

func scopeList() string {
	scopes := stage.Scopes()
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = string(s)
	}
	return strings.Join(parts, ", ")
}
