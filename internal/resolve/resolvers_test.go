package resolve

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseResolver(t *testing.T) {
	ok := map[string]string{
		"1.1.1.1":                    "1.1.1.1:53",
		" 8.8.8.8 ":                  "8.8.8.8:53",
		"9.9.9.10:5353":              "9.9.9.10:5353",
		"2606:4700:4700::1111":       "[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1111]:53":  "[2606:4700:4700::1111]:53",
		"1.1.1.1 # cloudflare":       "1.1.1.1:53",
		"8.8.4.4 ; google secondary": "8.8.4.4:53",
	}
	for in, want := range ok {
		got, err := parseResolver(in)
		if err != nil {
			t.Errorf("parseResolver(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseResolver(%q) = %q, want %q", in, got, want)
		}
	}

	// A hostname would have to be resolved by some other resolver first,
	// which is a dependency this stage must not have.
	for _, in := range []string{"", "dns.google", "1.1.1.1:0", "1.1.1.1:99999", "not-an-ip", "1.1.1.1:abc"} {
		if got, err := parseResolver(in); err == nil {
			t.Errorf("parseResolver(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseResolversDeduplicatesAndReportsJunk(t *testing.T) {
	resolvers, malformed := parseResolvers([]string{"1.1.1.1", "1.1.1.1:53", "8.8.8.8", "garbage", "dns.google"})
	if !slices.Equal(resolvers, []string{"1.1.1.1:53", "8.8.8.8:53"}) {
		t.Errorf("resolvers = %v, want the deduplicated pair", resolvers)
	}
	if !slices.Equal(malformed, []string{"garbage", "dns.google"}) {
		t.Errorf("malformed = %v, want both junk entries named", malformed)
	}
}

func TestLoadResolversFallsBackToTheBundledSet(t *testing.T) {
	got, err := LoadResolvers(context.Background(), LoadOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, DefaultResolvers) {
		t.Errorf("resolvers = %v, want the bundled set", got)
	}
}

func TestLoadResolversMergesInlineAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	body := "# public resolvers\n\n8.8.8.8\n9.9.9.10:53\n8.8.8.8\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadResolvers(context.Background(), LoadOptions{
		Inline: []string{"1.1.1.1"},
		File:   path,
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.10:53"}
	if !slices.Equal(got, want) {
		t.Errorf("resolvers = %v, want %v", got, want)
	}
}

func TestLoadResolversRejectsAFileOfJunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(path, []byte("not-an-ip\nalso-not\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResolvers(context.Background(), LoadOptions{File: path, Logger: discardLogger()}); err == nil {
		t.Error("a resolver file with nothing usable in it must fail, not fall back silently")
	}
}

// The list decides where every DNS query goes; fetching it over a channel
// anyone can rewrite would hand that decision away.
func TestLoadResolversRefusesPlainHTTP(t *testing.T) {
	_, err := LoadResolvers(context.Background(), LoadOptions{
		URL:    "http://example.com/resolvers.txt",
		Logger: discardLogger(),
	})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v, want a refusal naming https", err)
	}
}

func TestLoadResolversReportsAnUnreadableFile(t *testing.T) {
	_, err := LoadResolvers(context.Background(), LoadOptions{
		File:   filepath.Join(t.TempDir(), "missing.txt"),
		Logger: discardLogger(),
	})
	if err == nil {
		t.Error("an unreadable resolver file must fail loudly")
	}
}

func TestDefaultResolversAreWellFormed(t *testing.T) {
	for _, r := range DefaultResolvers {
		got, err := parseResolver(r)
		if err != nil {
			t.Errorf("bundled resolver %q is malformed: %v", r, err)
			continue
		}
		if got != r {
			t.Errorf("bundled resolver %q should already be normalized as %q", r, got)
		}
	}
}
