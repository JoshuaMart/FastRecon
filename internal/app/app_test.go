package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/config"
	"github.com/JoshuaMart/FastRecon/internal/logging"
	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/stage"
)

// baseConfig is a configuration that builds every stage without touching the
// network: the default resolvers are the built-in list, and validation is what
// would otherwise send queries.
func baseConfig(scope stage.Scope) *config.Config {
	return &config.Config{
		Domain:               "example.com",
		Scope:                scope,
		Timeout:              time.Minute,
		OutputMargin:         0.1,
		Sources:              []string{"crt"},
		SourceTimeout:        30 * time.Second,
		ValidateResolvers:    false,
		ResolverConcurrency:  10,
		ResolverRetries:      1,
		ResolverTimeout:      time.Second,
		WildcardProbes:       1,
		ResolverHealthBudget: time.Second,
		ScanMode:             config.ScanModeConnect,
		Ports:                "80,443",
		ScanConcurrency:      10,
		ScanRate:             100,
		ScanTimeout:          time.Second,
		ProbeConcurrency:     2,
		ProbeRate:            10,
		ProbeTimeout:         time.Second,
		ProbeMaxRedirects:    2,
		Output:               config.StdoutPath,
		Format:               report.FormatJSON,
		LogLevel:             "error",
		LogFormat:            "json",
	}
}

func newApp(t *testing.T, cfg *config.Config) *App {
	t.Helper()
	a, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestNewRequiresConfigAndLogger(t *testing.T) {
	if _, err := New(nil, logging.Discard()); err == nil {
		t.Error("New accepted a nil configuration")
	}
	if _, err := New(baseConfig(stage.ScopeEnum), nil); err == nil {
		t.Error("New accepted a nil logger")
	}
}

// The engines carrying an embedded dataset are the reason a served request
// used to cost ~110MB of retained heap and ~130ms before any work started.
// They must be built once and handed to every run.
func TestExpensiveEnginesAreBuiltOnce(t *testing.T) {
	a := newApp(t, baseConfig(stage.ScopeFull))

	if first, second := a.cdnRanges(), a.cdnRanges(); first != second {
		t.Error("cdnRanges built a second client; every run would reload the address ranges")
	}

	first, err := a.httpProber()
	if err != nil {
		t.Fatalf("httpProber: %v", err)
	}
	second, err := a.httpProber()
	if err != nil {
		t.Fatalf("httpProber: %v", err)
	}
	if first != second {
		t.Error("httpProber built a second prober; every run would reparse the technology fingerprints")
	}
}

// A scope that stops short of a stage must not build that stage's engine —
// an enumeration-only run has no reason to pay for the fingerprint dataset.
func TestNarrowScopeBuildsOnlyTheStagesItRuns(t *testing.T) {
	a := newApp(t, baseConfig(stage.ScopeEnum))

	stages, err := a.buildStages(context.Background(), a.cfg)
	if err != nil {
		t.Fatalf("buildStages: %v", err)
	}
	if stages.Enumerator == nil || stages.Excluder == nil {
		t.Fatal("an enum scope must still build enumeration and exclusion")
	}
	if stages.Resolver != nil || stages.PortScanner != nil || stages.Prober != nil {
		t.Error("an enum scope built a stage it does not run")
	}
	if a.prober != nil || a.cdn != nil {
		t.Error("an enum scope loaded an embedded dataset it never uses")
	}
}

func TestFullScopeBuildsEveryStage(t *testing.T) {
	a := newApp(t, baseConfig(stage.ScopeFull))

	stages, err := a.buildStages(context.Background(), a.cfg)
	if err != nil {
		t.Fatalf("buildStages: %v", err)
	}
	for name, built := range map[string]bool{
		"enumerator":   stages.Enumerator != nil,
		"excluder":     stages.Excluder != nil,
		"resolver":     stages.Resolver != nil,
		"port scanner": stages.PortScanner != nil,
		"prober":       stages.Prober != nil,
	} {
		if !built {
			t.Errorf("full scope did not build the %s", name)
		}
	}
}

// Every option must be read from the run configuration, so that a field made
// caller-settable in serve mode takes effect instead of being silently
// overridden by the process configuration.
func TestBuildStagesHonoursTheRunConfiguration(t *testing.T) {
	a := newApp(t, baseConfig(stage.ScopePorts))

	runCfg := a.cfg.Clone()
	runCfg.Ports = "not-a-port-list"

	if _, err := a.buildStages(context.Background(), runCfg); err == nil {
		t.Error("buildStages ignored the run configuration's ports and used the process one")
	}
}

func TestBuildStagesRejectsUnusableExclusions(t *testing.T) {
	cfg := baseConfig(stage.ScopeEnum)
	cfg.Exclude = []string{"re:("}
	a := newApp(t, cfg)

	_, err := a.buildStages(context.Background(), cfg)
	if err == nil {
		t.Fatal("buildStages accepted an exclusion pattern that does not compile")
	}
	if !strings.Contains(err.Error(), "exclusion") {
		t.Errorf("error = %v, want it to name the exclusions", err)
	}
}

// The resolver pool is loaded and health-checked once; a served instance must
// not redo it on every request.
func TestResolverPoolIsCached(t *testing.T) {
	a := newApp(t, baseConfig(stage.ScopeResolve))

	first, _, err := a.resolverPool(context.Background())
	if err != nil {
		t.Fatalf("resolverPool: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("resolverPool returned no resolver")
	}

	// Mutating the cached value is how a second load makes itself visible.
	a.pool[0] = "sentinel"
	second, _, err := a.resolverPool(context.Background())
	if err != nil {
		t.Fatalf("resolverPool: %v", err)
	}
	if second[0] != "sentinel" {
		t.Error("resolverPool reloaded the list instead of reusing the cached one")
	}
}

func TestCredentialsAreResolvedAndRedacted(t *testing.T) {
	const key = "not-a-real-key-0123456789"

	dir := t.TempDir()
	path := filepath.Join(dir, "provider-config.yaml")
	if err := os.WriteFile(path, []byte("chaos:\n  - "+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := baseConfig(stage.ScopeEnum)
	cfg.ProviderConfig = path
	cfg.Sources = []string{"chaos"}

	a := newApp(t, cfg)

	if got, ok := a.creds["chaos"]; !ok || got.Value != key {
		t.Fatalf("credential = %+v, want the key from the provider config", got)
	}
	// The origin is reportable; the value never is.
	if strings.Contains(a.creds["chaos"].Origin, key) {
		t.Error("the origin leaks the key it describes")
	}
	if got := a.Redactor().Redact("token=" + key); strings.Contains(got, key) {
		t.Errorf("redactor left the key in %q", got)
	}
}

func TestAccessorsExposeWhatTheHandlerNeeds(t *testing.T) {
	cfg := baseConfig(stage.ScopeEnum)
	a := newApp(t, cfg)

	if a.Config() != cfg {
		t.Error("Config must return the process configuration the handler clones")
	}
	if a.Redactor() == nil {
		t.Error("Redactor must never be nil: it is the last line of defence before output")
	}
}
