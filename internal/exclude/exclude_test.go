package exclude

import (
	"slices"
	"strings"
	"testing"
)

func kept(t *testing.T, patterns []string, strict bool, hosts ...string) []string {
	t.Helper()
	m, err := New(patterns, strict)
	if err != nil {
		t.Fatalf("New(%v): %v", patterns, err)
	}
	return m.Filter(hosts).Kept
}

func TestExactMatchIsCaseInsensitive(t *testing.T) {
	got := kept(t, []string{"Admin.Example.com"}, false, "admin.example.com", "api.example.com")
	if !slices.Equal(got, []string{"api.example.com"}) {
		t.Errorf("kept = %v, want only api.example.com", got)
	}
}

// A trailing dot is the same host; an exclusion that missed it would leave a
// host in scope that the operator believed was excluded.
func TestTrailingDotIsNormalized(t *testing.T) {
	got := kept(t, []string{"admin.example.com."}, false, "admin.example.com.", "api.example.com")
	if !slices.Equal(got, []string{"api.example.com"}) {
		t.Errorf("kept = %v, want only api.example.com", got)
	}
}

func TestWildcardCoversTheBaseByDefault(t *testing.T) {
	hosts := []string{"dev.example.com", "a.dev.example.com", "deep.a.dev.example.com", "devil.example.com", "api.example.com"}

	got := kept(t, []string{"*.dev.example.com"}, false, hosts...)
	if !slices.Equal(got, []string{"devil.example.com", "api.example.com"}) {
		t.Errorf("kept = %v, want the base and its children excluded, and devil.example.com untouched", got)
	}

	// Strict mode keeps the base itself in scope.
	got = kept(t, []string{"*.dev.example.com"}, true, hosts...)
	if !slices.Equal(got, []string{"dev.example.com", "devil.example.com", "api.example.com"}) {
		t.Errorf("kept = %v, want the base kept under strict wildcards", got)
	}
}

func TestRegexPatternIsCaseInsensitive(t *testing.T) {
	got := kept(t, []string{`re:^(staging|preprod)[0-9]*\.`}, false,
		"staging.example.com", "STAGING2.example.com", "preprod.example.com", "prod.example.com")
	if !slices.Equal(got, []string{"prod.example.com"}) {
		t.Errorf("kept = %v, want only prod.example.com", got)
	}
}

func TestFilterRecordsThePatternThatMatched(t *testing.T) {
	m, err := New([]string{"*.dev.example.com", "admin.example.com"}, false)
	if err != nil {
		t.Fatal(err)
	}
	res := m.Filter([]string{"a.dev.example.com", "admin.example.com", "api.example.com"})

	if len(res.Removed) != 2 {
		t.Fatalf("removed = %v, want 2", res.Removed)
	}
	byHost := map[string]string{}
	for _, r := range res.Removed {
		byHost[r.Host] = r.Pattern
	}
	if byHost["a.dev.example.com"] != "*.dev.example.com" {
		t.Errorf("wrong pattern recorded: %v", byHost)
	}
	if byHost["admin.example.com"] != "admin.example.com" {
		t.Errorf("wrong pattern recorded: %v", byHost)
	}
}

// A pattern matching nothing usually means a typo, and a typo in an exclusion
// means hosts got scanned that should not have been.
func TestUnusedPatternsAreReported(t *testing.T) {
	m, err := New([]string{"*.dev.example.com", "typo.example.com"}, false)
	if err != nil {
		t.Fatal(err)
	}
	res := m.Filter([]string{"a.dev.example.com"})
	if !slices.Equal(res.Unused, []string{"typo.example.com"}) {
		t.Errorf("unused = %v, want the typo pattern", res.Unused)
	}
}

func TestDuplicatePatternsAreCollapsed(t *testing.T) {
	m, err := New([]string{"admin.example.com", "admin.example.com", "  ", ""}, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 1 {
		t.Errorf("Len() = %d, want 1", m.Len())
	}
}

func TestInvalidPatternsAreAllReportedAtOnce(t *testing.T) {
	_, err := New([]string{"re:[unclosed", "mid*dle.example.com", "*."}, false)
	if err == nil {
		t.Fatal("New succeeded on invalid patterns")
	}
	msg := err.Error()
	for _, want := range []string{"[unclosed", "mid*dle.example.com", "*."} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

// A bare '*' inside a name is a common mistake; guessing at its meaning would
// silently exclude the wrong hosts.
func TestMidNameWildcardIsRejectedWithGuidance(t *testing.T) {
	_, err := New([]string{"api-*.example.com"}, false)
	if err == nil {
		t.Fatal("mid-name wildcard accepted")
	}
	if !strings.Contains(err.Error(), RegexPrefix) {
		t.Errorf("error %q should point at the regex form", err)
	}
}

func TestNoPatternsKeepsEverything(t *testing.T) {
	got := kept(t, nil, false, "a.example.com", "b.example.com")
	if len(got) != 2 {
		t.Errorf("kept = %v, want both hosts", got)
	}
}
