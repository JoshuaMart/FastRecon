package secrets

import (
	"regexp"
	"strings"
)

// Placeholder replaces a credential wherever one would otherwise be printed.
const Placeholder = "[REDACTED]"

// queryKeyRE matches a credential carried in a URL query string. Some sources
// authenticate that way — c99 puts the key in the URL — so an error message
// quoting the request URL would otherwise leak it verbatim into the report.
var queryKeyRE = regexp.MustCompile(`(?i)([?&](?:key|api_?key|token|access_?key|apitoken)=)[^&\s"']+`)

// Redactor scrubs known credential values, and anything shaped like one, out
// of text on its way to a log or a report.
type Redactor struct {
	values []string
}

// NewRedactor builds a redactor for the resolved credentials.
func NewRedactor(creds map[string]Credential) *Redactor {
	r := &Redactor{}
	for _, c := range creds {
		// Very short values would match everywhere and mangle the text.
		if len(c.Value) >= 8 {
			r.values = append(r.values, c.Value)
		}
	}
	return r
}

// Redact returns s with every known credential replaced.
//
// The query-string pass runs whether or not any credential value is known: a
// run whose provider config failed to load has no values to match, and is
// exactly the run whose source errors are most likely to quote a URL.
func (r *Redactor) Redact(s string) string {
	if s == "" {
		return s
	}
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, Placeholder)
	}
	return queryKeyRE.ReplaceAllString(s, "${1}"+Placeholder)
}

// RedactBytes scrubs a rendered document. It is the last line of defence
// before the report leaves the process: everything that reaches the report is
// meant to be redacted at the point it is created, and this catches whatever
// was not.
func (r *Redactor) RedactBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	out := r.Redact(string(data))
	return []byte(out)
}

// RedactError renders an error through the redactor, tolerating a nil error.
func (r *Redactor) RedactError(err error) string {
	if err == nil {
		return ""
	}
	return r.Redact(err.Error())
}
