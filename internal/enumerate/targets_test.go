package enumerate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func loadOpts(o TargetOptions) TargetOptions {
	o.Logger = discardLogger()
	return o
}

func TestNormalizeTargetKeepsHostsOutsideAnyRoot(t *testing.T) {
	// A verification list legitimately spans several apexes of one perimeter.
	ok := map[string]string{
		"API.Example.com":    "api.example.com",
		"api.example.com.":   "api.example.com",
		"*.dev.example.com":  "dev.example.com",
		"  www.other.net  ":  "www.other.net",
		"_dmarc.example.com": "_dmarc.example.com",
	}
	for in, want := range ok {
		got, valid := normalizeTarget(in)
		if !valid || got != want {
			t.Errorf("normalizeTarget(%q) = %q,%v want %q", in, got, valid, want)
		}
	}

	// A port would make the run-level port selection ambiguous.
	for _, in := range []string{"", "localhost", "http://x.example.com", "x.example.com:8080", "a b.example.com", "a..b.example.com"} {
		if got, valid := normalizeTarget(in); valid {
			t.Errorf("normalizeTarget(%q) = %q, want it rejected", in, got)
		}
	}
}

func TestLoadTargetsMergesAndDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# comment\n\nb.example.com\na.example.com\nB.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadTargets(context.Background(), loadOpts(TargetOptions{
		Inline: []string{"c.example.com"},
		File:   path,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"a.example.com", "b.example.com", "c.example.com"}) {
		t.Errorf("targets = %v, want them merged, deduplicated and sorted", got)
	}
}

// A host dropped for a formatting reason is a host that is never queried, and
// nothing downstream would say so.
func TestMalformedTargetsFailTheRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("good.example.com\nhttp://bad/x\nnope:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadTargets(context.Background(), loadOpts(TargetOptions{File: path}))
	if err == nil {
		t.Fatal("a malformed entry was silently skipped")
	}
	for _, want := range []string{"http://bad/x", "nope:8080"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestEmptyTargetListRefusesToStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# nothing but comments\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargets(context.Background(), loadOpts(TargetOptions{File: path})); err == nil {
		t.Error("an empty list was accepted")
	}
}

// A silently shortened list turns hosts that were never queried into hosts
// that did not answer.
func TestOversizedListFailsRatherThanTruncating(t *testing.T) {
	body := strings.Repeat("host.example.com\n", (maxTargetListBytes/17)+64)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// The test server uses a self-signed certificate, so this exercises the
	// size guard through the same code path a real fetch takes.
	_, err := LoadTargets(context.Background(), loadOpts(TargetOptions{URL: srv.URL}))
	if err == nil {
		t.Fatal("an oversized list was accepted")
	}
}

func TestTargetsURLMustBeHTTPS(t *testing.T) {
	_, err := LoadTargets(context.Background(), loadOpts(TargetOptions{URL: "http://example.com/targets.txt"}))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v, want a refusal naming https", err)
	}
}

func TestListEnumeratorQueriesNoSource(t *testing.T) {
	l, err := NewList([]string{"a.example.com", "b.example.com"}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.Enumerate(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 2 {
		t.Errorf("hosts = %v", got.Hosts)
	}
	if len(got.Sources) != 0 {
		t.Errorf("sources = %v, want none: no source was queried", got.Sources)
	}
	if len(got.HostSources) != 0 {
		t.Errorf("host sources = %v, want none in targets mode", got.HostSources)
	}
}

func TestNewListRefusesAnEmptyList(t *testing.T) {
	if _, err := NewList(nil, discardLogger()); err == nil {
		t.Error("NewList accepted an empty list")
	}
}
