package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolvePrecedence(t *testing.T) {
	cfg := writeFile(t, "provider-config.yaml", "chaos:\n  - from-file\n")
	keyFile := writeFile(t, "chaos.key", "from-secret-file\n")

	t.Setenv("FASTRECON_KEY_CHAOS_FILE", keyFile)
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Lowest: the per-key secret file.
	if got := r.Resolve([]string{"chaos"})["chaos"]; got.Value != "from-file" {
		t.Errorf("value = %q, want the provider config to beat the secret file", got.Value)
	}

	// The upstream environment variable beats the provider config.
	t.Setenv("CHAOS_API_KEY", "from-upstream-env")
	if got := r.Resolve([]string{"chaos"})["chaos"]; got.Value != "from-upstream-env" {
		t.Errorf("value = %q, want the upstream environment variable", got.Value)
	}

	// The namespaced form wins over everything.
	t.Setenv("FASTRECON_KEY_CHAOS", "from-namespaced-env")
	got := r.Resolve([]string{"chaos"})["chaos"]
	if got.Value != "from-namespaced-env" {
		t.Errorf("value = %q, want the namespaced environment variable", got.Value)
	}
	if !strings.Contains(got.Origin, "FASTRECON_KEY_CHAOS") {
		t.Errorf("origin = %q, want it to name the winning channel", got.Origin)
	}
}

func TestSecretFileIsUsedWhenNothingElseIsSet(t *testing.T) {
	keyFile := writeFile(t, "c99.key", "  file-key  \n")
	t.Setenv("FASTRECON_KEY_C99_FILE", keyFile)

	r, err := NewResolver("")
	if err != nil {
		t.Fatal(err)
	}
	got := r.Resolve([]string{"c99"})["c99"]
	if got.Value != "file-key" {
		t.Errorf("value = %q, want the trimmed file contents", got.Value)
	}
}

// An empty variable is an absence, not a credential: a deployment that unsets
// a key must not end up sending an empty one.
func TestEmptyEnvValueIsNotACredential(t *testing.T) {
	t.Setenv("CHAOS_API_KEY", "   ")
	r, err := NewResolver("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Resolve([]string{"chaos"})["chaos"]; ok {
		t.Error("an empty environment value was treated as a credential")
	}
}

func TestUnreadableProviderConfigIsAnError(t *testing.T) {
	if _, err := NewResolver(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a provider config that cannot be read must fail loudly")
	}
}

func TestTakeReportsMissingSourcesWithoutValues(t *testing.T) {
	creds := map[string]Credential{"crt": {Source: "crt", Value: "secret-value", Origin: "env:CRT_API_KEY"}}
	inv := Take([]string{"crt", "chaos"}, creds)

	if inv.Configured["crt"] != "env:CRT_API_KEY" {
		t.Errorf("configured = %v, want the origin", inv.Configured)
	}
	for _, origin := range inv.Configured {
		if strings.Contains(origin, "secret-value") {
			t.Error("the inventory must never carry a credential value")
		}
	}
	if len(inv.Missing) != 1 || inv.Missing[0] != "chaos" {
		t.Errorf("missing = %v, want [chaos]", inv.Missing)
	}
}

func TestRedactorScrubsKnownValues(t *testing.T) {
	r := NewRedactor(map[string]Credential{"chaos": {Value: "abcdef1234567890"}})
	got := r.Redact("request failed with key abcdef1234567890 attached")
	if strings.Contains(got, "abcdef1234567890") {
		t.Errorf("redacted = %q, the value survived", got)
	}
	if !strings.Contains(got, Placeholder) {
		t.Errorf("redacted = %q, want the placeholder", got)
	}
}

// c99 authenticates through the query string, so an error quoting the request
// URL leaks the key verbatim unless the URL itself is scrubbed.
func TestRedactorScrubsCredentialsInQueryStrings(t *testing.T) {
	r := NewRedactor(nil)
	for _, in := range []string{
		"https://api.c99.nl/subdomainfinder?key=deadbeefcafe&domain=example.com",
		"GET https://x.example/v1?api_key=sekrit-token-value returned 500",
		"https://x.example/v1?foo=1&token=abc123&bar=2",
	} {
		got := r.Redact(in)
		for _, leaked := range []string{"deadbeefcafe", "sekrit-token-value", "abc123"} {
			if strings.Contains(got, leaked) {
				t.Errorf("Redact(%q) = %q, leaked %q", in, got, leaked)
			}
		}
		if !strings.Contains(got, Placeholder) {
			t.Errorf("Redact(%q) = %q, want the placeholder", in, got)
		}
	}
	// The rest of the URL must survive, or the message stops being useful.
	got := r.Redact("https://api.c99.nl/subdomainfinder?key=deadbeefcafe&domain=example.com")
	if !strings.Contains(got, "domain=example.com") {
		t.Errorf("Redact stripped too much: %q", got)
	}
}

// Short values would match everywhere and mangle unrelated text.
func TestRedactorIgnoresVeryShortValues(t *testing.T) {
	r := NewRedactor(map[string]Credential{"x": {Value: "ab"}})
	if got := r.Redact("a stable build"); got != "a stable build" {
		t.Errorf("Redact mangled unrelated text: %q", got)
	}
}

func TestRedactErrorToleratesNil(t *testing.T) {
	if got := NewRedactor(nil).RedactError(nil); got != "" {
		t.Errorf("RedactError(nil) = %q, want empty", got)
	}
}
