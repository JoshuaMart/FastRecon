package config

import (
	"os"
	"strings"
)

// EnvName derives the environment variable for a flag: "http-timeout" becomes
// FASTRECON_HTTP_TIMEOUT. The mapping is mechanical on purpose — there is no
// per-option table to fall out of sync with the flag set.
func EnvName(flag string) string {
	return EnvPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
}

func lookupEnv(flag string) (string, bool) {
	v, ok := os.LookupEnv(EnvName(flag))
	if !ok {
		return "", false
	}
	// An explicitly empty variable is a value, not an absence: it is how a
	// deployment unsets an option inherited from a config file.
	return v, true
}
