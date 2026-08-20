package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Format selects how a report is rendered. Every sink receives the same bytes,
// so the format is a property of the run, not of the destination.
type Format string

const (
	// FormatJSON is one indented document: the default, and the only format
	// that carries the whole report.
	FormatJSON Format = "json"
	// FormatJSONL is one host per line, for scopes too large to hold in
	// memory downstream. Run metadata is not in the stream — it goes to the
	// log, which carries the same counters.
	FormatJSONL Format = "jsonl"
	// FormatText is a human summary.
	FormatText Format = "text"
)

// ParseFormat resolves a format name.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case FormatJSON:
		return FormatJSON, nil
	case FormatJSONL:
		return FormatJSONL, nil
	case FormatText:
		return FormatText, nil
	default:
		return "", fmt.Errorf("unknown format %q (valid: json, jsonl, text)", s)
	}
}

func (f Format) String() string { return string(f) }

// Ext returns the file extension conventionally used for the format.
func (f Format) Ext() string {
	switch f {
	case FormatJSONL:
		return ".jsonl"
	case FormatText:
		return ".txt"
	default:
		return ".json"
	}
}

// Render encodes the report in the given format.
func (r *Report) Render(f Format) ([]byte, error) {
	switch f {
	case FormatJSON:
		return renderJSON(r)
	case FormatJSONL:
		return renderJSONL(r)
	case FormatText:
		return renderText(r), nil
	default:
		return nil, fmt.Errorf("unknown format %q", f)
	}
}

func renderJSON(r *Report) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, fmt.Errorf("encode report: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func renderJSONL(r *Report) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for i := range r.Hosts {
		if err := enc.Encode(r.Hosts[i]); err != nil {
			return nil, fmt.Errorf("encode host %s: %w", r.Hosts[i].Host, err)
		}
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func renderText(r *Report) []byte {
	var b strings.Builder

	fmt.Fprintf(&b, "run      %s\n", r.Run.ID)
	fmt.Fprintf(&b, "domain   %s\n", r.Run.Domain)
	fmt.Fprintf(&b, "scope    %s (%s)\n", r.Run.Scope, strings.Join(r.Run.Stages, " > "))
	fmt.Fprintf(&b, "duration %s\n", formatMillis(r.Run.Duration))
	status := "complete"
	if r.Run.TruncatedByTimeout {
		status = "TRUNCATED BY TIMEOUT"
	} else if !r.Run.Completed {
		status = "INCOMPLETE"
	}
	fmt.Fprintf(&b, "status   %s\n", status)

	if len(r.Sources) > 0 {
		b.WriteString("\nsources\n")
		sources := append([]Source(nil), r.Sources...)
		sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
		for _, s := range sources {
			line := fmt.Sprintf("  %-18s %-15s %6d", s.Name, s.Status, s.Found)
			if s.Partial {
				line += " (partial)"
			}
			if s.Error != "" {
				line += "  " + s.Error
			}
			b.WriteString(line + "\n")
		}
	}

	fmt.Fprintf(&b, "\nstats\n")
	for _, kv := range []struct {
		k string
		v int
	}{
		{"enumerated", r.Stats.Enumerated},
		{"excluded", r.Stats.Excluded},
		{"in scope", r.Stats.InScope},
		{"live", r.Stats.Live},
		{"dead", r.Stats.Dead},
		{"wildcard", r.Stats.Wildcard},
		{"open ports", r.Stats.OpenPorts},
		{"http services", r.Stats.HTTPServices},
	} {
		fmt.Fprintf(&b, "  %-14s %d\n", kv.k, kv.v)
	}

	if len(r.Hosts) > 0 {
		b.WriteString("\nhosts\n")
		for _, h := range r.Hosts {
			fmt.Fprintf(&b, "  %-45s %-9s %s\n", h.Host, h.Status, hostDetail(h))
		}
	}

	if len(r.Warnings) > 0 {
		b.WriteString("\nwarnings\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  - %s\n", w)
		}
	}
	return []byte(strings.TrimRight(b.String(), "\n"))
}

func hostDetail(h Host) string {
	switch {
	case h.Status == StatusDead:
		return h.Reason
	case len(h.Ports) > 0:
		parts := make([]string, 0, len(h.Ports)+1)
		for _, p := range h.Ports {
			if p.HTTP != nil {
				parts = append(parts, fmt.Sprintf("%d/%s(%d)", p.Port, p.HTTP.Scheme, p.HTTP.StatusCode))
				continue
			}
			parts = append(parts, fmt.Sprintf("%d", p.Port))
		}
		if cdn := cdnDetail(h.CDN); cdn != "" {
			parts = append(parts, cdn)
		}
		return strings.Join(parts, " ")
	default:
		return strings.TrimSpace(strings.Join(h.Addresses, " ") + " " + cdnDetail(h.CDN))
	}
}

// cdnDetail renders the CDN providers behind a host, marking a port list that
// was deliberately narrowed so it is not read as an exhaustive scan.
func cdnDetail(cdns []CDN) string {
	if len(cdns) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cdns))
	for _, c := range cdns {
		name := c.Name
		if c.ScanLimited {
			name += ",ports-limited"
		}
		parts = append(parts, name)
	}
	return "[cdn:" + strings.Join(parts, " ") + "]"
}

func formatMillis(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}
