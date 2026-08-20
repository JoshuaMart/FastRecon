package config

import (
	"os"
	"strings"
)

// Environment labels recorded in the report.
const (
	EnvLocal              = "local"
	EnvContainer          = "container"
	EnvServerlessJob      = "serverless-job"
	EnvServerlessFunction = "serverless-function"
)

// DetectEnvironment labels the runtime for the report.
//
// Only local and container are detectable from inside the process. A
// serverless job and a plain container look the same to the runtime, so the
// job and function labels come from the deployment setting --environment
// (FASTRECON_ENVIRONMENT); the deploy manifests in deploy/ do that. Guessing
// from undocumented platform variables would silently mislabel runs the day
// the platform renames one.
func DetectEnvironment(explicit string, serveMode bool) string {
	if e := strings.TrimSpace(explicit); e != "" {
		return e
	}
	if serveMode {
		return EnvServerlessFunction
	}
	if inContainer() {
		return EnvContainer
	}
	return EnvLocal
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(data)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods")
}
