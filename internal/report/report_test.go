package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/stage"
)

func sample(t *testing.T) *Report {
	t.Helper()
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := New("01ABC", "example.com", stage.ScopeFull, "1.2.3", "serverless-job", started)
	r.Stats.Enumerated = 3
	r.Stats.Excluded = 1
	r.Stats.InScope = 2
	r.Sources = []Source{{Name: "chaos", Status: SourceOK, Found: 3}}
	r.Hosts = []Host{
		{
			Host:      "api.example.com",
			Status:    StatusLive,
			Addresses: []string{"93.184.216.34"},
			CDN:       []CDN{{Name: "cloudflare", Type: "waf", Addresses: []string{"93.184.216.34"}, ScanLimited: true}},
			Ports: []Port{
				{Port: 443, Protocol: "tcp", State: "open", HTTP: &HTTP{URL: "https://api.example.com", Scheme: "https", StatusCode: 200}},
				{Port: 22, Protocol: "tcp", State: "open"},
			},
		},
		{Host: "old.example.com", Status: StatusDead, Reason: ReasonNXDomain},
	}
	r.Finish(started.Add(7 * time.Second))
	return r
}

func TestFinishDerivesCounters(t *testing.T) {
	r := sample(t)
	if r.Stats.Live != 1 || r.Stats.Dead != 1 {
		t.Errorf("live/dead = %d/%d, want 1/1", r.Stats.Live, r.Stats.Dead)
	}
	if r.Stats.OpenPorts != 2 {
		t.Errorf("open ports = %d, want 2", r.Stats.OpenPorts)
	}
	if r.Stats.HTTPServices != 1 {
		t.Errorf("http services = %d, want 1: only one port answered HTTP", r.Stats.HTTPServices)
	}
	// Pre-host counters are the pipeline's to set and must survive Finish.
	if r.Stats.Enumerated != 3 || r.Stats.Excluded != 1 || r.Stats.InScope != 2 {
		t.Errorf("pre-host counters were overwritten: %+v", r.Stats)
	}
	if r.Run.Duration != 7000 {
		t.Errorf("duration = %dms, want 7000", r.Run.Duration)
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	data, err := sample(t).Render(FormatJSON)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if back.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", back.SchemaVersion, SchemaVersion)
	}
	if len(back.Hosts) != 2 {
		t.Errorf("hosts = %d, want 2", len(back.Hosts))
	}
	if back.Hosts[0].Ports[0].HTTP.Scheme != "https" {
		t.Error("the working scheme must survive a round trip")
	}
	if len(back.Hosts[0].CDN) != 1 || !back.Hosts[0].CDN[0].ScanLimited {
		t.Error("the CDN determination and its scan_limited marker must survive a round trip")
	}
}

// A port list narrowed to the web ports must never read as an exhaustive scan.
func TestRenderTextMarksNarrowedCDNScans(t *testing.T) {
	out, err := sample(t).Render(FormatText)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "cdn:cloudflare") {
		t.Error("the CDN provider is missing from the text output")
	}
	if !strings.Contains(s, "ports-limited") {
		t.Error("a deliberately narrowed port list must be marked in the text output")
	}
}

func TestRenderJSONLIsOneHostPerLine(t *testing.T) {
	data, err := sample(t).Render(FormatJSONL)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per host", len(lines))
	}
	for i, line := range lines {
		var h Host
		if err := json.Unmarshal(line, &h); err != nil {
			t.Errorf("line %d is not a host object: %v", i, err)
		}
	}
}

func TestRenderTextMarksTruncatedRuns(t *testing.T) {
	r := sample(t)
	r.Run.Completed = false
	r.Run.TruncatedByTimeout = true
	r.Warnf("stage %s: run deadline reached", stage.PortScan)

	out, err := r.Render(FormatText)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "TRUNCATED BY TIMEOUT") {
		t.Error("a truncated run must be obvious in the text output")
	}
	if !strings.Contains(s, "deadline reached") {
		t.Error("warnings are missing from the text output")
	}
}

// An indented report becomes hundreds of log lines that a collector may
// reorder or drop; one line carries the same document intact.
func TestRenderJSONCompactIsOneLine(t *testing.T) {
	data, err := sample(t).Render(FormatJSONCompact)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if bytes.Contains(data, []byte("\n")) {
		t.Errorf("compact output spans %d lines", bytes.Count(data, []byte("\n"))+1)
	}

	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("compact output is not valid JSON: %v", err)
	}
	// Unlike jsonl, nothing is dropped.
	if len(back.Hosts) != 2 || len(back.Sources) != 1 || back.Stats.Enumerated != 3 {
		t.Errorf("compact output lost part of the document: %+v", back.Stats)
	}

	indented, err := sample(t).Render(FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) >= len(indented) {
		t.Errorf("compact is %d bytes against %d indented, want it smaller", len(data), len(indented))
	}
}

func TestParseFormat(t *testing.T) {
	for _, in := range []string{"json", "JSON", "json-compact", "jsonl", "text"} {
		if _, err := ParseFormat(in); err != nil {
			t.Errorf("ParseFormat(%q): %v", in, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("ParseFormat(yaml) succeeded, want an error")
	}
}
