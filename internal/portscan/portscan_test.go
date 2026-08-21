package portscan

import (
	"context"
	"log/slog"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JoshuaMart/FastRecon/internal/ratelimit"
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

func newScanner(t *testing.T, skipCDN bool, scan func(context.Context, []string, portSpec, *ratelimit.Limiter) (scanResult, error)) *Scanner {
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
	n := newScanner(t, true, func(_ context.Context, addresses []string, _ portSpec, _ *ratelimit.Limiter) (scanResult, error) {
		passes = append(passes, addresses)
		return scanResult{open: map[string][]int{"1.2.3.4": {80, 443}}}, nil
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
	n := newScanner(t, true, func(context.Context, []string, portSpec, *ratelimit.Limiter) (scanResult, error) {
		return scanResult{open: map[string][]int{"1.2.3.4": {443, 80}, "5.6.7.8": {80, 8080}}}, nil
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
	n := newScanner(t, true, func(context.Context, []string, portSpec, *ratelimit.Limiter) (scanResult, error) {
		called = true
		return scanResult{}, nil
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
	n := newScanner(t, true, func(context.Context, []string, portSpec, *ratelimit.Limiter) (scanResult, error) {
		return scanResult{open: map[string][]int{"1.2.3.4": {80}}}, nil
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

func TestFeedIsPortMajor(t *testing.T) {
	// Address-major order would hammer one host with the whole port list
	// back to back.
	queue := make(chan target)
	go feed(context.Background(), queue, []string{"1.1.1.1", "2.2.2.2"}, []int{80, 443})

	var got []target
	for t := range queue {
		got = append(got, t)
	}
	want := []target{
		{"1.1.1.1", 80}, {"2.2.2.2", 80},
		{"1.1.1.1", 443}, {"2.2.2.2", 443},
	}
	if !slices.Equal(got, want) {
		t.Errorf("feed = %v, want %v", got, want)
	}
}

// The feeder must not block forever once the run is over.
func TestFeedStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	queue := make(chan target)
	done := make(chan struct{})
	go func() { feed(ctx, queue, []string{"1.1.1.1"}, []int{80, 443, 8080}); close(done) }()

	for range queue {
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("feed did not return after its context ended")
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
		portSpec{List: strconv.Itoa(openPort) + "," + strconv.Itoa(closedPort)}, ratelimit.New(0))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(found.open["127.0.0.1"], openPort) {
		t.Errorf("found = %v, want the listening port %d", found, openPort)
	}
	if slices.Contains(found.open["127.0.0.1"], closedPort) {
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

// The worker count is what --scan-concurrency promises. A goroutine per probe
// would allocate a stack for every (address, port) pair up front: a full
// sweep is millions of them, and the process is killed for memory long before
// the deadline it was budgeted for.
func TestScanConnectGoroutinesStayBounded(t *testing.T) {
	const (
		workers = 8
		ports   = 20000
	)
	s := &Scanner{
		opts: Options{
			Concurrency: workers,
			Rate:        1_000_000,
			Timeout:     200 * time.Millisecond,
			Logger:      discardLogger(),
		},
	}

	baseline := runtime.NumGoroutine()
	var peak atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				if n := int64(runtime.NumGoroutine()); n > peak.Load() {
					peak.Store(n)
				}
				runtime.Gosched()
			}
		}
	}()

	// Loopback high ports refuse instantly, so this measures scheduling, not
	// network waits.
	if _, err := s.scanConnect(context.Background(), []string{"127.0.0.1"}, portSpec{List: "20000-" + strconv.Itoa(20000+ports-1)}, ratelimit.New(0)); err != nil {
		t.Fatal(err)
	}
	close(stop)

	// Workers, the feeder, the sampler, and the test's own goroutines — far
	// below one per probe.
	if limit := int64(baseline + workers + 50); peak.Load() > limit {
		t.Errorf("peak goroutines = %d, want at most %d for %d probes at concurrency %d",
			peak.Load(), limit, ports, workers)
	}
}

// A warm instance serves many requests from one Scanner. Holding the limiter
// on the scanner and stopping it at the end of a run left every later run
// unlimited, which is invisible until a target notices.
func TestRateLimitStillAppliesOnASecondScan(t *testing.T) {
	var seen []*ratelimit.Limiter
	s := newScanner(t, false, func(_ context.Context, _ []string, _ portSpec, l *ratelimit.Limiter) (scanResult, error) {
		seen = append(seen, l)
		if !l.Wait(context.Background()) {
			t.Error("the limiter refused a token on a live context")
		}
		return scanResult{open: map[string][]int{"1.2.3.4": {80}}}, nil
	})
	s.opts.Rate = 100

	hosts := []report.Host{{Host: "a.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}}}
	for run := range 2 {
		if _, err := s.Scan(context.Background(), hosts); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}

	if len(seen) != 2 {
		t.Fatalf("scan ran %d times, want 2", len(seen))
	}
	if seen[0] == seen[1] {
		t.Error("both runs shared one limiter; the second would run unlimited once the first stopped it")
	}
}

// An address is scanned once and mapped onto every host resolving to it.
// Without recording which address a port came from, one service behind ten
// names is indistinguishable from ten services.
func TestPortsRecordTheAddressTheyWereFoundOn(t *testing.T) {
	n := newScanner(t, false, func(context.Context, []string, portSpec, *ratelimit.Limiter) (scanResult, error) {
		return scanResult{open: map[string][]int{"1.2.3.4": {8080}, "5.6.7.8": {8080, 443}}}, nil
	})

	hosts := []report.Host{
		// Two names, one address: the classic CNAME fan-in.
		{Host: "a.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}},
		{Host: "b.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}},
		// One name, two addresses.
		{Host: "c.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4", "5.6.7.8"}},
	}

	res, err := n.Scan(context.Background(), hosts)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]report.Port{}
	for _, h := range res.Hosts {
		got[h.Host] = h.Ports
	}

	for _, name := range []string{"a.example.com", "b.example.com"} {
		p := got[name]
		if len(p) != 1 || !slices.Equal(p[0].Addresses, []string{"1.2.3.4"}) {
			t.Errorf("%s port = %+v, want it to name the shared address", name, p)
		}
	}

	// The port open on both of c's addresses records both.
	c := got["c.example.com"]
	if len(c) != 2 {
		t.Fatalf("c ports = %+v, want 443 and 8080", c)
	}
	for _, p := range c {
		switch p.Port {
		case 8080:
			if !slices.Equal(p.Addresses, []string{"1.2.3.4", "5.6.7.8"}) {
				t.Errorf("8080 addresses = %v, want both", p.Addresses)
			}
		case 443:
			if !slices.Equal(p.Addresses, []string{"5.6.7.8"}) {
				t.Errorf("443 addresses = %v, want only the address it was found on", p.Addresses)
			}
		}
	}
}

// The four buckets must always sum to scanned: without that, "everything
// refused" stays true over a set of ports that was never tried.
func TestScanCountersSumToWhatWasAttempted(t *testing.T) {
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

	s := &Scanner{opts: Options{
		Concurrency: 4,
		Rate:        1000,
		Timeout:     2 * time.Second,
		Logger:      discardLogger(),
	}}
	// The listening port plus four that refuse instantly.
	spec := portSpec{List: strconv.Itoa(openPort) + ",1,2,3,4"}
	got, err := s.scanConnect(context.Background(), []string{"127.0.0.1"}, spec, ratelimit.New(0))
	if err != nil {
		t.Fatal(err)
	}

	tally := got.tally["127.0.0.1"]
	if tally == nil {
		t.Fatal("no counters recorded for a probed address")
	}
	if sum := tally.Open + tally.Refused + tally.Filtered + tally.Unknown; sum != tally.Scanned {
		t.Errorf("buckets sum to %d, scanned is %d (%+v)", sum, tally.Scanned, tally)
	}
	if tally.Scanned != 5 {
		t.Errorf("scanned = %d, want the five ports attempted", tally.Scanned)
	}
	if tally.Open != 1 {
		t.Errorf("open = %d, want the one listening port", tally.Open)
	}
}

// A host narrowed to the web ports counts those, not the full selection.
func TestScanCountersReflectTheNarrowedSweep(t *testing.T) {
	n := newScanner(t, true, func(_ context.Context, addresses []string, ports portSpec, _ *ratelimit.Limiter) (scanResult, error) {
		list, _ := (&Scanner{opts: Options{Logger: discardLogger()}}).expand(ports)
		out := scanResult{open: map[string][]int{}, tally: map[string]*report.Scan{}}
		for _, a := range addresses {
			out.tally[a] = &report.Scan{Scanned: len(list), Refused: len(list)}
		}
		return out, nil
	})
	n.cdn = nil // no CDN data: exercise the plain path
	n.opts.SkipCDN = true

	hosts := []report.Host{{Host: "a.example.com", Status: report.StatusLive, Addresses: []string{"1.2.3.4"}}}
	res, err := n.Scan(context.Background(), hosts)
	if err != nil {
		t.Fatal(err)
	}
	sc := res.Hosts[0].Scan
	if sc == nil {
		t.Fatal("a probed host carries no counters")
	}
	if sc.Scanned != sc.Refused || sc.Scanned == 0 {
		t.Errorf("scan = %+v, want the attempted count", sc)
	}
}

// A zeroed object would read as a sweep that tried and found nothing.
func TestScanIsAbsentWhenNothingWasProbed(t *testing.T) {
	n := newScanner(t, true, func(context.Context, []string, portSpec, *ratelimit.Limiter) (scanResult, error) {
		return scanResult{}, nil
	})
	res, err := n.Scan(context.Background(), []report.Host{
		{Host: "dead.example.com", Status: report.StatusDead},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Hosts[0].Scan != nil {
		t.Errorf("scan = %+v, want it absent on a host that was never probed", res.Hosts[0].Scan)
	}
}
