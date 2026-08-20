// Package stage defines the pipeline stages and the scope ladder that selects them.
package stage

import "fmt"

// Stage is a single step of the recon pipeline.
type Stage string

const (
	Enumerate Stage = "enumerate"
	Exclude   Stage = "exclude"
	Resolve   Stage = "resolve"
	PortScan  Stage = "portscan"
	HTTPProbe Stage = "httpprobe"
)

// Scope selects how far up the ladder a run goes. Scopes form a strict ladder:
// each one runs every stage of the scope below it plus one more. Arbitrary
// combinations are deliberately not expressible — probing without a port scan
// would mean inventing a default port set, which looks like discovery but is
// really an assumption.
type Scope string

const (
	ScopeEnum    Scope = "enum"
	ScopeResolve Scope = "resolve"
	ScopePorts   Scope = "ports"
	ScopeFull    Scope = "full"
)

var ladder = []struct {
	scope  Scope
	stages []Stage
}{
	{ScopeEnum, []Stage{Enumerate, Exclude}},
	{ScopeResolve, []Stage{Enumerate, Exclude, Resolve}},
	{ScopePorts, []Stage{Enumerate, Exclude, Resolve, PortScan}},
	{ScopeFull, []Stage{Enumerate, Exclude, Resolve, PortScan, HTTPProbe}},
}

// Scopes returns every valid scope, ordered from narrowest to widest.
func Scopes() []Scope {
	out := make([]Scope, 0, len(ladder))
	for _, l := range ladder {
		out = append(out, l.scope)
	}
	return out
}

// ParseScope resolves a scope name, rejecting anything outside the ladder.
func ParseScope(s string) (Scope, error) {
	for _, l := range ladder {
		if string(l.scope) == s {
			return l.scope, nil
		}
	}
	return "", fmt.Errorf("unknown stage scope %q (valid: %s)", s, join(Scopes()))
}

// Stages returns the ordered stages a scope runs.
func (s Scope) Stages() []Stage {
	for _, l := range ladder {
		if l.scope == s {
			return l.stages
		}
	}
	return nil
}

// Includes reports whether the scope runs the given stage.
func (s Scope) Includes(st Stage) bool {
	for _, have := range s.Stages() {
		if have == st {
			return true
		}
	}
	return false
}

func (s Scope) String() string { return string(s) }

// StageNames renders a scope's stages as strings, for the run report.
func (s Scope) StageNames() []string {
	stages := s.Stages()
	out := make([]string, len(stages))
	for i, st := range stages {
		out[i] = string(st)
	}
	return out
}

func join(scopes []Scope) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += ", "
		}
		out += string(s)
	}
	return out
}
