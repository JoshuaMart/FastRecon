// Package exclude removes out-of-scope hosts before any network activity.
//
// Exclusions are applied to the enumeration output, so an excluded host is
// never resolved, scanned or probed — the point is to not touch it at all,
// not merely to hide it from the report.
package exclude

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/JoshuaMart/FastRecon/internal/pipeline"
	"github.com/JoshuaMart/FastRecon/internal/report"
)

// RegexPrefix marks a pattern as a regular expression.
const RegexPrefix = "re:"

type kind int

const (
	kindExact kind = iota
	kindWildcard
	kindRegex
)

type pattern struct {
	raw   string
	kind  kind
	value string // exact host, or the suffix behind a wildcard
	re    *regexp.Regexp
	hits  int
}

// Matcher applies a set of exclusion patterns.
type Matcher struct {
	patterns []*pattern
	// strictWildcard makes *.x.example.com exclude hosts under x.example.com
	// without excluding x.example.com itself.
	strictWildcard bool
}

// New compiles the patterns. Every problem is reported at once, so a bad
// exclusion list is fixed in one pass rather than one error per run.
func New(patterns []string, strictWildcard bool) (*Matcher, error) {
	m := &Matcher{strictWildcard: strictWildcard}
	var errs []error
	seen := make(map[string]bool, len(patterns))

	for _, raw := range patterns {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true

		p, err := compile(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m.patterns = append(m.patterns, p)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return m, nil
}

func compile(raw string) (*pattern, error) {
	if expr, ok := strings.CutPrefix(raw, RegexPrefix); ok {
		// (?i) up front: host matching is case-insensitive throughout, and a
		// pattern that behaved differently from the other two forms would be
		// a trap.
		re, err := regexp.Compile("(?i)" + expr)
		if err != nil {
			return nil, fmt.Errorf("exclusion pattern %q: %w", raw, err)
		}
		return &pattern{raw: raw, kind: kindRegex, re: re}, nil
	}

	lower := strings.ToLower(strings.TrimSuffix(raw, "."))
	if suffix, ok := strings.CutPrefix(lower, "*."); ok {
		if suffix == "" {
			return nil, fmt.Errorf("exclusion pattern %q has nothing behind the wildcard", raw)
		}
		return &pattern{raw: raw, kind: kindWildcard, value: suffix}, nil
	}
	if strings.Contains(lower, "*") {
		return nil, fmt.Errorf("exclusion pattern %q: a wildcard is only supported as a leading '*.' label, use %s<regexp> for anything else", raw, RegexPrefix)
	}
	if lower == "" {
		return nil, fmt.Errorf("exclusion pattern %q is empty", raw)
	}
	return &pattern{raw: raw, kind: kindExact, value: lower}, nil
}

// Name identifies the stage implementation.
func (m *Matcher) Name() string { return "patterns" }

// Len returns the number of compiled patterns.
func (m *Matcher) Len() int { return len(m.patterns) }

// Filter splits hosts into those kept and those excluded, recording which
// pattern removed each host and which patterns matched nothing.
func (m *Matcher) Filter(hosts []string) pipeline.Filtered {
	out := pipeline.Filtered{Kept: make([]string, 0, len(hosts))}

	for _, host := range hosts {
		if p := m.match(host); p != nil {
			p.hits++
			out.Removed = append(out.Removed, report.Excluded{Host: host, Pattern: p.raw})
			continue
		}
		out.Kept = append(out.Kept, host)
	}

	// A pattern that matched nothing is almost always a typo, and a typo in
	// an exclusion means hosts were scanned that should not have been.
	for _, p := range m.patterns {
		if p.hits == 0 {
			out.Unused = append(out.Unused, p.raw)
		}
	}
	return out
}

// match returns the first pattern excluding host, or nil.
func (m *Matcher) match(host string) *pattern {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range m.patterns {
		switch p.kind {
		case kindExact:
			if h == p.value {
				return p
			}
		case kindWildcard:
			if strings.HasSuffix(h, "."+p.value) {
				return p
			}
			if !m.strictWildcard && h == p.value {
				return p
			}
		case kindRegex:
			if p.re.MatchString(h) {
				return p
			}
		}
	}
	return nil
}
