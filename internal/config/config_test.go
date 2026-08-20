package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func load(t *testing.T, args ...string) (*Config, error) {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse args: %v", err)
	}
	return Load(fs)
}

func mustLoad(t *testing.T, args ...string) *Config {
	t.Helper()
	cfg, err := load(t, args...)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestEnvName(t *testing.T) {
	for flag, want := range map[string]string{
		"domain":       "FASTRECON_DOMAIN",
		"http-timeout": "FASTRECON_HTTP_TIMEOUT",
		"scan-mode":    "FASTRECON_SCAN_MODE",
	} {
		if got := EnvName(flag); got != want {
			t.Errorf("EnvName(%q) = %q, want %q", flag, got, want)
		}
	}
}

func TestPrecedenceFlagOverEnvOverFileOverDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("domain: file.example.com\nports: top-1000\nscan-mode: syn\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default wins when nothing else is set.
	t.Setenv("FASTRECON_DOMAIN", "env.example.com")
	cfg := mustLoad(t, "--config", path)
	if cfg.ScanMode != ScanModeSYN {
		t.Errorf("scan-mode = %q, want the file value %q", cfg.ScanMode, ScanModeSYN)
	}
	if cfg.Ports != "top-1000" {
		t.Errorf("ports = %q, want the file value", cfg.Ports)
	}
	// Env beats the file.
	if cfg.Domain != "env.example.com" {
		t.Errorf("domain = %q, want the environment value", cfg.Domain)
	}
	// Flag beats the environment.
	cfg = mustLoad(t, "--config", path, "-d", "flag.example.com")
	if cfg.Domain != "flag.example.com" {
		t.Errorf("domain = %q, want the flag value", cfg.Domain)
	}
	// Untouched options keep their default.
	if cfg.Timeout != 30*time.Minute {
		t.Errorf("timeout = %s, want the 30m default", cfg.Timeout)
	}
}

func TestEnvListSplitting(t *testing.T) {
	t.Setenv("FASTRECON_EXCLUDE", "a.example.com, *.dev.example.com\nre:^staging")
	cfg := mustLoad(t, "-d", "example.com")
	want := []string{"a.example.com", "*.dev.example.com", "re:^staging"}
	if len(cfg.Exclude) != len(want) {
		t.Fatalf("exclude = %v, want %v", cfg.Exclude, want)
	}
	for i := range want {
		if cfg.Exclude[i] != want[i] {
			t.Errorf("exclude[%d] = %q, want %q", i, cfg.Exclude[i], want[i])
		}
	}
}

// A regexp repeat count contains a comma. Splitting on it yields two halves
// that both still compile, so the run would quietly scan hosts the operator
// excluded — the worst possible failure for an exclusion.
func TestRegexExclusionsSurviveEnvSplitting(t *testing.T) {
	t.Setenv("FASTRECON_EXCLUDE", `re:^a{1,3}\.example\.com$`+"\nadmin.example.com, www.example.com")
	cfg := mustLoad(t, "-d", "example.com")

	want := []string{`re:^a{1,3}\.example\.com$`, "admin.example.com", "www.example.com"}
	if len(cfg.Exclude) != len(want) {
		t.Fatalf("exclude = %#v, want %#v", cfg.Exclude, want)
	}
	for i := range want {
		if cfg.Exclude[i] != want[i] {
			t.Errorf("exclude[%d] = %q, want %q", i, cfg.Exclude[i], want[i])
		}
	}
}

// The engine matches source names case-sensitively and calls os.Exit on an
// empty selection, so names are normalized before they can get there.
func TestSourceNamesAreNormalized(t *testing.T) {
	cfg := mustLoad(t, "-d", "example.com", "--sources", "Crt", "--sources", " SUBMD ", "--exclude-sources", "Chaos")
	if len(cfg.Sources) != 2 || cfg.Sources[0] != "crt" || cfg.Sources[1] != "submd" {
		t.Errorf("sources = %v, want them lowercased and trimmed", cfg.Sources)
	}
	if len(cfg.ExcludeSources) != 1 || cfg.ExcludeSources[0] != "chaos" {
		t.Errorf("exclude-sources = %v, want them lowercased", cfg.ExcludeSources)
	}
}

// The engine takes whole seconds and truncates, so anything under a second
// would silently become no ceiling at all.
func TestSubSecondSourceTimeoutRejected(t *testing.T) {
	if _, err := load(t, "-d", "example.com", "--source-timeout", "500ms"); err == nil {
		t.Error("a sub-second source timeout was accepted")
	}
	if _, err := load(t, "-d", "example.com", "--source-timeout", "1s"); err != nil {
		t.Errorf("a one-second source timeout was rejected: %v", err)
	}
}

// Header values may legitimately contain a comma, so they split on newlines
// only — otherwise "Accept: a,b" would silently become two broken headers.
func TestHeaderEnvSplitsOnNewlinesOnly(t *testing.T) {
	t.Setenv("FASTRECON_PROBE_HEADER", "Accept: text/html,application/json\nX-Trace: 1")
	cfg := mustLoad(t, "-d", "example.com")
	if len(cfg.ProbeHeaders) != 2 {
		t.Fatalf("probe headers = %v, want 2 entries", cfg.ProbeHeaders)
	}
	if cfg.ProbeHeaders[0] != "Accept: text/html,application/json" {
		t.Errorf("header[0] = %q, comma was split", cfg.ProbeHeaders[0])
	}
}

func TestUnknownConfigKeyWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("domain: example.com\nporst: top-100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := mustLoad(t, "--config", path)
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "porst") {
		t.Errorf("warnings = %v, want one warning naming the unknown key", cfg.Warnings)
	}
}

func TestExcludeFileMergesWithInlinePatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.txt")
	body := "# comment\n\n*.dev.example.com\nadmin.example.com\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := mustLoad(t, "-d", "example.com", "--exclude", "inline.example.com", "--exclude-file", path)
	want := []string{"inline.example.com", "*.dev.example.com", "admin.example.com"}
	if len(cfg.Exclude) != len(want) {
		t.Fatalf("exclude = %v, want %v", cfg.Exclude, want)
	}
}

func TestInvalidValuesAreReportedTogether(t *testing.T) {
	_, err := load(t, "-d", "example.com", "--scan-mode", "sneaky", "--timeout", "0s", "--probe-concurrency", "0")
	if err == nil {
		t.Fatal("Load succeeded on an invalid configuration")
	}
	msg := err.Error()
	for _, want := range []string{"scan-mode", "timeout", "probe-concurrency"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q; every problem must surface at once", msg, want)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"Example.COM":       "example.com",
		"example.com.":      "example.com",
		"*.example.com":     "example.com",
		"  example.com  ":   "example.com",
		"sub.example.co.uk": "sub.example.co.uk",
	}
	for in, want := range ok {
		got, err := NormalizeDomain(in)
		if err != nil {
			t.Errorf("NormalizeDomain(%q) failed: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{"", "localhost", "https://example.com", "example.com/path", "exa mple.com", "-bad.example.com", "café.fr"} {
		if got, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) = %q, want an error", in, got)
		}
	}
}

func TestWebhookHeadersWithoutURLRejected(t *testing.T) {
	if _, err := load(t, "-d", "example.com", "--webhook-header", "X-Token: abc"); err == nil {
		t.Error("webhook-header accepted without webhook-url")
	}
}

func TestMalformedHeaderRejected(t *testing.T) {
	if _, err := load(t, "-d", "example.com", "--probe-header", "NoColon"); err == nil {
		t.Error("malformed probe header accepted")
	}
}

func TestDetectEnvironmentPrefersExplicitLabel(t *testing.T) {
	if got := DetectEnvironment("serverless-job", false); got != EnvServerlessJob {
		t.Errorf("DetectEnvironment = %q, want the explicit label", got)
	}
	if got := DetectEnvironment("", true); got != EnvServerlessFunction {
		t.Errorf("DetectEnvironment in serve mode = %q, want %q", got, EnvServerlessFunction)
	}
}
