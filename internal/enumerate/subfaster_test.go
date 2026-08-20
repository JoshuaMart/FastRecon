package enumerate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"

	"github.com/JoshuaMart/FastRecon/internal/report"
	"github.com/JoshuaMart/FastRecon/internal/secrets"
)

func TestNormalize(t *testing.T) {
	const domain = "example.com"

	ok := map[string]string{
		"API.Example.com":     "api.example.com",
		"api.example.com.":    "api.example.com",
		"*.dev.example.com":   "dev.example.com",
		"  api.example.com  ": "api.example.com",
		"example.com":         "example.com",
		// Underscores are legitimate in DNS names and must survive.
		"_dmarc.example.com": "_dmarc.example.com",
	}
	for in, want := range ok {
		got, valid := normalize(in, domain)
		if !valid {
			t.Errorf("normalize(%q) rejected the value", in)
			continue
		}
		if got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}

	// Out of scope, or not a hostname at all.
	for _, in := range []string{
		"", "notexample.com", "example.com.evil.net", "evil.net",
		"http://api.example.com", "api.example.com:443", "user@example.com",
		"api..example.com",
	} {
		if got, valid := normalize(in, domain); valid {
			t.Errorf("normalize(%q) = %q, want it rejected", in, got)
		}
	}
}

func TestNormalizeConvertsInternationalizedNames(t *testing.T) {
	got, ok := normalize("café.example.com", "example.com")
	if !ok {
		t.Fatal("an internationalized name was rejected")
	}
	if !strings.HasPrefix(got, "xn--") {
		t.Errorf("normalize = %q, want the punycode form", got)
	}
}

func TestRateLimited(t *testing.T) {
	for _, in := range []string{
		"unexpected status code 429",
		"Rate limit exceeded",
		"too many requests, retry later",
		"monthly quota reached",
	} {
		if !rateLimited(in) {
			t.Errorf("rateLimited(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "connection refused", "unexpected status code 500"} {
		if rateLimited(in) {
			t.Errorf("rateLimited(%q) = true, want false", in)
		}
	}
}

func TestEffectiveRemovesExclusions(t *testing.T) {
	got := effective([]string{"chaos", "CRT", "submd"}, []string{"crt"})
	if len(got) != 2 || got[0] != "chaos" || got[1] != "submd" {
		t.Errorf("effective = %v, want chaos and submd", got)
	}
}

func TestValidateSourcesNamesTheUnknownOnes(t *testing.T) {
	err := validateSources([]string{"chaos", "notasource", "crt"})
	if err == nil {
		t.Fatal("validateSources accepted an unknown source")
	}
	if !strings.Contains(err.Error(), "notasource") {
		t.Errorf("error %q does not name the offending source", err)
	}
	if strings.Contains(err.Error(), "chaos") {
		t.Errorf("error %q blames a valid source", err)
	}
	if err := validateSources([]string{"chaos", "crt", "submd", "c99", "securitytrails"}); err != nil {
		t.Errorf("the required sources must all exist: %v", err)
	}
}

func statuses(t *testing.T, s *Subfaster, stats map[string]subscraping.Statistics, errs map[string][]string, timedOut bool) map[string]report.Source {
	t.Helper()
	out := map[string]report.Source{}
	for _, src := range s.sourceStatuses(stats, errs, timedOut) {
		out[src.Name] = src
	}
	return out
}

func TestSourceStatusMapping(t *testing.T) {
	s := &Subfaster{opts: Options{
		Sources:     []string{"chaos", "crt", "submd", "c99", "securitytrails"},
		Credentials: map[string]secrets.Credential{"c99": {Source: "c99", Value: "k"}},
	}}

	stats := map[string]subscraping.Statistics{
		"crt":            {Results: 30, TimeTaken: 150 * time.Millisecond},
		"submd":          {Results: 18, Errors: 2},
		"chaos":          {Skipped: true},
		"c99":            {Errors: 1},
		"securitytrails": {},
	}
	errs := map[string][]string{
		"c99":   {"unexpected status code 429"},
		"submd": {"one page failed"},
	}

	got := statuses(t, s, stats, errs, true)

	if got["crt"].Status != report.SourceOK || got["crt"].Found != 30 {
		t.Errorf("crt = %+v, want ok with 30 results", got["crt"])
	}
	// Errors alongside results is a degraded success, not a failure.
	if got["submd"].Status != report.SourceOK || !got["submd"].Partial {
		t.Errorf("submd = %+v, want ok and partial", got["submd"])
	}
	// A keyed source with no credential is skipped for a known reason.
	if got["chaos"].Status != report.SourceSkippedNoKey {
		t.Errorf("chaos = %+v, want skipped_no_key", got["chaos"])
	}
	// Throttling is not a generic error: it says the source refused, not that
	// it had nothing.
	if got["c99"].Status != report.SourceRateLimited {
		t.Errorf("c99 = %+v, want rate_limited", got["c99"])
	}
	// Nothing at all, while the run was out of time.
	if got["securitytrails"].Status != report.SourceTimeout {
		t.Errorf("securitytrails = %+v, want timeout", got["securitytrails"])
	}
}

func TestSourceStatusErrorWithoutResultsIsAFailure(t *testing.T) {
	s := &Subfaster{opts: Options{Sources: []string{"crt"}}}
	got := statuses(t, s, map[string]subscraping.Statistics{"crt": {Errors: 3}}, map[string][]string{"crt": {"boom"}}, false)
	if got["crt"].Status != report.SourceError {
		t.Errorf("crt = %+v, want error", got["crt"])
	}
	if got["crt"].Error != "boom" {
		t.Errorf("error = %q, want the underlying message", got["crt"].Error)
	}
}

// A selected source the engine never reported on must still appear, otherwise
// a source that vanished looks the same as one that was never asked.
func TestSelectedSourcesAlwaysAppear(t *testing.T) {
	s := &Subfaster{opts: Options{Sources: []string{"chaos", "crt"}}}
	got := statuses(t, s, map[string]subscraping.Statistics{}, nil, false)
	if len(got) != 2 {
		t.Errorf("sources = %v, want both selected sources present", got)
	}
}

func TestEnumerationBudgetFollowsTheStageDeadline(t *testing.T) {
	if got := enumerationBudget(context.Background()); got != defaultMaxEnumeration {
		t.Errorf("budget without a deadline = %s, want the default", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if got := enumerationBudget(ctx); got <= 0 || got > time.Minute {
		t.Errorf("budget = %s, want it bounded by the stage deadline", got)
	}

	expired, cancel2 := context.WithTimeout(context.Background(), -time.Second)
	defer cancel2()
	if got := enumerationBudget(expired); got > time.Millisecond {
		t.Errorf("budget past the deadline = %s, want it to close immediately", got)
	}
}

// The engine calls os.Exit when it is handed an empty source list.
func TestEmptySelectionIsRejectedBeforeReachingTheEngine(t *testing.T) {
	_, err := NewSubfaster(Options{
		Sources:        []string{"crt"},
		ExcludeSources: []string{"crt"},
		SourceTimeout:  time.Second,
		Logger:         discardLogger(),
	})
	if err == nil {
		t.Fatal("an empty source selection was accepted")
	}
	if !strings.Contains(err.Error(), "no sources selected") {
		t.Errorf("error = %q, want it to explain the empty selection", err)
	}
}

func TestAvailableListsTheRequiredSources(t *testing.T) {
	byName := map[string]SourceInfo{}
	for _, s := range Available() {
		byName[s.Name] = s
	}
	for _, want := range []string{"chaos", "securitytrails", "c99", "submd", "crt"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("source %q is missing from the engine", want)
		}
	}
	if byName["chaos"].Key != "required" {
		t.Errorf("chaos key requirement = %q, want required", byName["chaos"].Key)
	}
	// crt.name and sub.md work without a key but accept one for better
	// results, which is why an enumeration with no credentials at all still
	// returns data.
	for _, name := range []string{"crt", "submd"} {
		if byName[name].Key != "optional" {
			t.Errorf("%s key requirement = %q, want optional", name, byName[name].Key)
		}
	}
}
