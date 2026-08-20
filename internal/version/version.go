// Package version carries the build identity, injected at link time.
package version

import (
	"fmt"
	"runtime/debug"
)

// Set with -ldflags "-X github.com/JoshuaMart/FastRecon/internal/version.Version=..."
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

func init() {
	if Commit != "" {
		return
	}
	// Fall back to the VCS stamp the toolchain embeds for `go build` and
	// `go install` outside the release pipeline.
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			Commit = s.Value
		case "vcs.time":
			Date = s.Value
		}
	}
}

// String renders the full build identity.
func String() string {
	s := Version
	if Commit != "" {
		short := Commit
		if len(short) > 12 {
			short = short[:12]
		}
		s += " (" + short + ")"
	}
	if Date != "" {
		s += " built " + Date
	}
	return s
}

// UserAgent is the default User-Agent for outbound requests.
func UserAgent() string {
	return fmt.Sprintf("FastRecon/%s", Version)
}
