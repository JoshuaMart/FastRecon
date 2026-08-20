package portscan

import (
	"context"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/report"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(99)}))
}

func TestParsePorts(t *testing.T) {
	named := map[string]portSpec{
		PortsTop100: {TopPorts: "100"},
		"TOP-1000":  {TopPorts: "1000"},
		PortsFull:   {TopPorts: "full"},
	}
	for in, want := range named {
		got, err := parsePorts(in)
		if err != nil {
			t.Errorf("parsePorts(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parsePorts(%q) = %+v, want %+v", in, got, want)
		}
	}

	web, err := parsePorts(PortsWeb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(web.List, "8443") || web.TopPorts != "" {
		t.Errorf("web selection = %+v, want an explicit list containing 8443", web)
	}

	explicit, err := parsePorts("80,443,8000-8100")
	if err != nil {
		t.Fatal(err)
	}
	if explicit.List != "80,443,8000-8100" {
		t.Errorf("explicit = %+v, want the expression passed through", explicit)
	}
}

// A typo in a port list must be caught here, naming the offending part,
// rather than deep inside the engine.
func TestParsePortsRejectsBadExpressions(t *testing.T) {
	for _, in := range []string{"", "80,,443", "80-", "http", "0", "70000", "8100-8000", "80,abc"} {
		if got, err := parsePorts(in); err == nil {
			t.Errorf("parsePorts(%q) = %+v, want an error", in, got)
		}
	}
}

func TestIndexAddressesSkipsWhatCannotBeScanned(t *testing.T) {
	hosts := []report.Host{
		{Host: "a.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}},
		{Host: "b.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4", "5.6.7.8"}},
		{Host: "dead.example.com", Status: report.StatusDead},
		// A wildcard artifact is not a host; scanning it proves nothing.
		{Host: "junk.example.com", Status: report.StatusWildcard, Addresses: []string{"9.9.9.9"}},
		{Host: "bad.example.com", Status: report.StatusLive, Addresses: []string{"not-an-ip"}},
	}

	got := indexAddresses(hosts)
	if len(got) != 2 {
		t.Fatalf("addresses = %v, want only the two live ones", got)
	}
	if !slices.Equal(got["1.2.3.4"], []int{0, 1}) {
		t.Errorf("1.2.3.4 = %v, want both hosts sharing it", got["1.2.3.4"])
	}
	if _, ok := got["9.9.9.9"]; ok {
		t.Error("a wildcard artifact was queued for scanning")
	}
}

func TestSplitByEdge(t *testing.T) {
	addresses := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	edges := map[string]edge{"2.2.2.2": {Provider: "cloudflare", Type: "waf"}}

	plain, behind := splitByEdge(addresses, edges, true)
	if !slices.Equal(plain, []string{"1.1.1.1", "3.3.3.3"}) || !slices.Equal(behind, []string{"2.2.2.2"}) {
		t.Errorf("split = %v / %v, want the CDN address separated", plain, behind)
	}

	// With the restriction lifted, everything gets the full sweep.
	plain, behind = splitByEdge(addresses, edges, false)
	if len(plain) != 3 || len(behind) != 0 {
		t.Errorf("split = %v / %v, want no restriction", plain, behind)
	}
}

func TestCDNEntriesGroupPerProvider(t *testing.T) {
	addresses := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	edges := map[string]edge{
		"1.1.1.1": {Provider: "cloudflare", Type: "waf"},
		"2.2.2.2": {Provider: "aws", Type: "cloud"},
		// Same provider as the first: they must land in one entry.
		"3.3.3.3": {Provider: "cloudflare", Type: "waf"},
	}

	got := cdnEntries(addresses, edges, true)
	if len(got) != 2 {
		t.Fatalf("entries = %+v, want one per provider", got)
	}
	if got[0].Name != "aws" || got[1].Name != "cloudflare" {
		t.Errorf("entries are not sorted by provider: %+v", got)
	}
	if !slices.Equal(got[1].Addresses, []string{"1.1.1.1", "3.3.3.3"}) {
		t.Errorf("cloudflare addresses = %v, want both", got[1].Addresses)
	}
	if !got[1].ScanLimited {
		t.Error("scan_limited must be set when the sweep was narrowed")
	}
	if cdnEntries(addresses, nil, false) != nil {
		t.Error("no CDN means no entries")
	}
}

func newScanner(t *testing.T, skipCDN bool, scan func(context.Context, []string, portSpec) (map[string][]int, error)) *Scanner {
	t.Helper()
	return &Scanner{
		opts:  Options{SkipCDN: skipCDN, Mode: ModeConnect, Logger: discardLogger()},
		ports: portSpec{TopPorts: "100"},
		scan:  scan,
	}
}

// One address shared by several subdomains is scanned once and mapped back
// onto every one of them.
func TestScanMapsResultsBackOntoSharedAddresses(t *testing.T) {
	var passes [][]string
	n := newScanner(t, true, func(_ context.Context, addresses []string, _ portSpec) (map[string][]int, error) {
		passes = append(passes, addresses)
		return map[string][]int{"1.2.3.4": {80, 443}}, nil
	})

	hosts := []report.Host{
		{Host: "a.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}},
		{Host: "b.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}},
		{Host: "dead.example.com", Status: report.StatusDead},
	}

	res, err := n.Scan(context.Background(), hosts)
	if err != nil {
		t.Fatal(err)
	}
	if len(passes) != 1 || len(passes[0]) != 1 {
		t.Fatalf("passes = %v, want the shared address scanned once", passes)
	}
	for _, i := range []int{0, 1} {
		if len(res.Hosts[i].Ports) != 2 {
			t.Errorf("%s ports = %+v, want both mapped back", res.Hosts[i].Host, res.Hosts[i].Ports)
		}
	}
	if res.Hosts[2].Ports != nil {
		t.Error("a dead host must not gain ports")
	}
}

func TestScanDeduplicatesPortsAcrossAHostAddresses(t *testing.T) {
	n := newScanner(t, true, func(context.Context, []string, portSpec) (map[string][]int, error) {
		return map[string][]int{"1.2.3.4": {443, 80}, "5.6.7.8": {80, 8080}}, nil
	})

	hosts := []report.Host{{Host: "a.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4", "5.6.7.8"}}}
	res, err := n.Scan(context.Background(), hosts)
	if err != nil {
		t.Fatal(err)
	}

	var ports []int
	for _, p := range res.Hosts[0].Ports {
		ports = append(ports, p.Port)
		if p.Protocol != "tcp" || p.State != "open" {
			t.Errorf("port %+v is missing its protocol or state", p)
		}
	}
	if !slices.Equal(ports, []int{80, 443, 8080}) {
		t.Errorf("ports = %v, want them deduplicated and sorted", ports)
	}
}

func TestScanWithNoLiveHostDoesNothing(t *testing.T) {
	called := false
	n := newScanner(t, true, func(context.Context, []string, portSpec) (map[string][]int, error) {
		called = true
		return nil, nil
	})

	res, err := n.Scan(context.Background(), []report.Host{{Host: "dead.example.com", Status: report.StatusDead}})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("the engine was started with nothing to scan")
	}
	if len(res.Hosts) != 1 {
		t.Error("the hosts must pass through untouched")
	}
}

func TestScanReportsTruncationWhenTheDeadlinePasses(t *testing.T) {
	n := newScanner(t, true, func(context.Context, []string, portSpec) (map[string][]int, error) {
		return map[string][]int{"1.2.3.4": {80}}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := n.Scan(ctx, []report.Host{{Host: "a.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("a scan cut short must report itself truncated")
	}
	if len(res.Warnings) == 0 {
		t.Error("a truncated scan must warn")
	}
}

// A SYN scan the process cannot perform finds nothing at all, which reads
// exactly like a host with nothing listening.
func TestSynModeIsRefusedNotSilentlyDowngraded(t *testing.T) {
	_, err := New(Options{
		Mode:        ModeSYN,
		Ports:       PortsTop100,
		Concurrency: 10,
		Rate:        100,
		Timeout:     time.Second,
		Logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("syn mode was accepted; it must refuse rather than scan differently than asked")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("error = %q, want it to point at the usable mode", err)
	}
}

func TestExpandPorts(t *testing.T) {
	s := &Scanner{opts: Options{Logger: discardLogger()}}

	got, err := s.expand(portSpec{List: "443,80,80,8000-8002"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int{80, 443, 8000, 8001, 8002}) {
		t.Errorf("expand = %v, want it sorted and deduplicated", got)
	}

	top, err := s.expand(portSpec{TopPorts: "100"})
	if err != nil {
		t.Fatal(err)
	}
	if len(top) < 90 || !slices.Contains(top, 443) {
		t.Errorf("top-100 expanded to %d ports, want the nmap selection", len(top))
	}

	full, err := s.expand(portSpec{TopPorts: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 65535 {
		t.Errorf("full = %d ports, want 65535", len(full))
	}
}

func TestExpandPortsAppliesExclusions(t *testing.T) {
	s := &Scanner{opts: Options{ExcludePorts: "443,8001", Logger: discardLogger()}}
	got, err := s.expand(portSpec{List: "80,443,8000-8002"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int{80, 8000, 8002}) {
		t.Errorf("expand = %v, want the excluded ports removed", got)
	}
}

func TestPlanIsPortMajor(t *testing.T) {
	// Address-major order would hammer one host with the whole port list
	// back to back.
	got := plan([]string{"1.1.1.1", "2.2.2.2"}, []int{80, 443})
	want := []target{
		{"1.1.1.1", 80}, {"2.2.2.2", 80},
		{"1.1.1.1", 443}, {"2.2.2.2", 443},
	}
	if !slices.Equal(got, want) {
		t.Errorf("plan = %v, want %v", got, want)
	}
}

// A refusal is a definitive answer; only inconclusive results are retried.
func TestConnectScanFindsAListeningPortAndNotAClosedOne(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback:", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	openPort := ln.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot reserve a closed port:", err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()

	s := &Scanner{opts: Options{
		Concurrency: 4,
		Rate:        1000,
		Timeout:     2 * time.Second,
		Logger:      discardLogger(),
	}}

	found, err := s.scanConnect(context.Background(), []string{"127.0.0.1"},
		portSpec{List: strconv.Itoa(openPort) + "," + strconv.Itoa(closedPort)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(found["127.0.0.1"], openPort) {
		t.Errorf("found = %v, want the listening port %d", found, openPort)
	}
	if slices.Contains(found["127.0.0.1"], closedPort) {
		t.Errorf("found = %v, must not contain the closed port %d", found, closedPort)
	}
}

func TestNewRejectsUnusableOptions(t *testing.T) {
	base := Options{Mode: ModeConnect, Ports: PortsTop100, Concurrency: 10, Rate: 100, Timeout: time.Second, Logger: discardLogger()}
	for name, mutate := range map[string]func(*Options){
		"no logger":      func(o *Options) { o.Logger = nil },
		"no concurrency": func(o *Options) { o.Concurrency = 0 },
		"no rate":        func(o *Options) { o.Rate = 0 },
		"no timeout":     func(o *Options) { o.Timeout = 0 },
		"bad ports":      func(o *Options) { o.Ports = "http" },
		"bad exclusion":  func(o *Options) { o.ExcludePorts = "nope" },
	} {
		opts := base
		mutate(&opts)
		if _, err := New(opts); err == nil {
			t.Errorf("New accepted options with %s", name)
		}
	}
	if _, err := New(base); err != nil {
		t.Errorf("New rejected valid options: %v", err)
	}
}
