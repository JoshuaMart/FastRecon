// Package secrets resolves source API keys and keeps them out of the output.
//
// The container image never contains a credential — it is built by CI and
// published — so every key arrives at runtime, through one of the channels
// below.
package secrets

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// EnvPrefix is the namespaced spelling of a source key:
// FASTRECON_KEY_CHAOS. The upstream spelling (CHAOS_API_KEY) is accepted too.
const EnvPrefix = "FASTRECON_KEY_"

// Credential is a resolved key and where it came from. The value is never
// logged or serialized; Origin is what gets reported.
type Credential struct {
	Source string
	Value  string
	Origin string
}

// Resolver resolves credentials for a set of sources.
type Resolver struct {
	providerConfig map[string][]string
	configPath     string
}

// NewResolver loads the optional provider config file. Its format is the
// subfinder/subfaster one — a source name mapped to a list of keys — so an
// existing file works unchanged.
func NewResolver(providerConfigPath string) (*Resolver, error) {
	r := &Resolver{configPath: providerConfigPath}
	if providerConfigPath == "" {
		return r, nil
	}
	data, err := os.ReadFile(providerConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read provider config: %w", err)
	}
	if err := yaml.Unmarshal(data, &r.providerConfig); err != nil {
		return nil, fmt.Errorf("parse provider config %s: %w", providerConfigPath, err)
	}
	return r, nil
}

// Resolve returns the credential for each source that has one.
//
// Precedence, highest first:
//
//	FASTRECON_KEY_<SOURCE>        namespaced environment variable
//	<SOURCE>_API_KEY              upstream environment variable
//	provider config file          the mounted YAML
//	FASTRECON_KEY_<SOURCE>_FILE   a file holding the key, for mounted secrets
func (r *Resolver) Resolve(sources []string) map[string]Credential {
	out := make(map[string]Credential, len(sources))
	for _, source := range sources {
		if c, ok := r.resolveOne(source); ok {
			out[source] = c
		}
	}
	return out
}

func (r *Resolver) resolveOne(source string) (Credential, bool) {
	upper := strings.ToUpper(source)

	if v, ok := nonEmptyEnv(EnvPrefix + upper); ok {
		return Credential{source, v, "env:" + EnvPrefix + upper}, true
	}
	if v, ok := nonEmptyEnv(upper + "_API_KEY"); ok {
		return Credential{source, v, "env:" + upper + "_API_KEY"}, true
	}
	if keys := r.providerConfig[source]; len(keys) > 0 && strings.TrimSpace(keys[0]) != "" {
		return Credential{source, strings.TrimSpace(keys[0]), "provider-config:" + r.configPath}, true
	}
	if path, ok := nonEmptyEnv(EnvPrefix + upper + "_FILE"); ok {
		data, err := os.ReadFile(path)
		if err == nil {
			if v := strings.TrimSpace(string(data)); v != "" {
				return Credential{source, v, "file:" + path}, true
			}
		}
	}
	return Credential{}, false
}

func nonEmptyEnv(name string) (string, bool) {
	v := strings.TrimSpace(os.Getenv(name))
	return v, v != ""
}

// Export publishes the resolved keys under the upstream environment names,
// which is the only channel the enumeration engine reads.
//
// This mutates the process environment, so it is process-global: a build that
// runs several enumerations concurrently in one process must configure the
// keys once, up front, not per run.
func Export(creds map[string]Credential) error {
	for source, c := range creds {
		if err := os.Setenv(strings.ToUpper(source)+"_API_KEY", c.Value); err != nil {
			return fmt.Errorf("export key for %s: %w", source, err)
		}
	}
	return nil
}

// Inventory reports which sources have a key and where it came from. It never
// includes a value, not even truncated.
type Inventory struct {
	Configured map[string]string // source -> origin
	Missing    []string
}

// Take builds the inventory for a set of sources.
func Take(sources []string, creds map[string]Credential) Inventory {
	inv := Inventory{Configured: make(map[string]string, len(creds))}
	for _, s := range sources {
		if c, ok := creds[s]; ok {
			inv.Configured[s] = c.Origin
			continue
		}
		inv.Missing = append(inv.Missing, s)
	}
	return inv
}
