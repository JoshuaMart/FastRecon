package resolve

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/retryabledns"

	"github.com/JoshuaMart/FastRecon/internal/report"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(99)}))
}

// fakeDNS answers from a fixed table. Any name not in the table is treated as
// a wildcard hit when its parent has a wildcard entry, which is how a real
// wildcard record behaves.
type fakeDNS struct {
	mu        sync.Mutex
	answers   map[string]*retryabledns.DNSData
	wildcards map[string]*retryabledns.DNSData
	nxdomain  map[string]bool
	failures  map[string]bool
	queries   int
}

func (f *fakeDNS) query(host string) (*retryabledns.DNSData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries++

	if f.failures[host] {
		return nil, context.DeadlineExceeded
	}
	if d, ok := f.answers[host]; ok {
		return d, nil
	}
	for parent, d := range f.wildcards {
		if strings.HasSuffix(host, "."+parent) {
			return d, nil
		}
	}
	if f.nxdomain[host] {
		return &retryabledns.DNSData{Host: host, StatusCode: "NXDOMAIN"}, nil
	}
	return &retryabledns.DNSData{Host: host, StatusCode: "NOERROR"}, nil
}

func newResolver(t *testing.T, domain string, f *fakeDNS) *DNSX {
	t.Helper()
	return &DNSX{
		opts: Options{
			Domain:         domain,
			Concurrency:    4,
			WildcardProbes: 3,
			Logger:         discardLogger(),
		},
		query: f.query,
	}
}

func byHost(hosts []report.Host) map[string]report.Host {
	out := make(map[string]report.Host, len(hosts))
	for _, h := range hosts {
		out[h.Host] = h
	}
	return out
}

func TestResolveClassifiesHosts(t *testing.T) {
	f := &fakeDNS{
		answers: map[string]*retryabledns.DNSData{
			"api.example.com": {Host: "api.example.com", A: []string{"93.184.216.34"}, StatusCode: "NOERROR"},
			"v6.example.com":  {Host: "v6.example.com", AAAA: []string{"2606:2800::1"}, StatusCode: "NOERROR"},
			// Exists, has an alias, but no address: a dangling CNAME.
			"old.example.com": {Host: "old.example.com", CNAME: []string{"bucket.s3.amazonaws.com."}, StatusCode: "NOERROR"},
		},
		nxdomain: map[string]bool{"gone.example.com": true},
		failures: map[string]bool{"slow.example.com": true},
	}
	r := newResolver(t, "example.com", f)

	res, err := r.Resolve(context.Background(), []string{
		"api.example.com", "v6.example.com", "old.example.com", "gone.example.com", "slow.example.com", "nodata.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	got := byHost(res.Hosts)
	if len(res.Hosts) != 6 {
		t.Fatalf("hosts = %d, want every input host reported", len(res.Hosts))
	}
	if got["api.example.com"].Status != report.StatusLive {
		t.Errorf("api = %+v, want live", got["api.example.com"])
	}
	// An AAAA-only host is live: v6-only services exist.
	if got["v6.example.com"].Status != report.StatusLive {
		t.Errorf("v6 = %+v, want live", got["v6.example.com"])
	}
	if got["gone.example.com"].Reason != report.ReasonNXDomain {
		t.Errorf("gone = %+v, want nxdomain", got["gone.example.com"])
	}
	if got["slow.example.com"].Reason != report.ReasonTimeout {
		t.Errorf("slow = %+v, want timeout", got["slow.example.com"])
	}
	// NOERROR with no records is not NXDOMAIN: the name exists.
	if got["nodata.example.com"].Reason != report.ReasonNoAnswer {
		t.Errorf("nodata = %+v, want no_answer", got["nodata.example.com"])
	}

	// The dangling alias must survive with its target intact — that is the
	// finding, and dropping it would erase it.
	dangling := got["old.example.com"]
	if dangling.Status != report.StatusDead || dangling.Reason != report.ReasonNoAnswer {
		t.Errorf("old = %+v, want dead/no_answer", dangling)
	}
	if !slices.Equal(dangling.CNAME, []string{"bucket.s3.amazonaws.com"}) {
		t.Errorf("cname = %v, want the normalized target kept", dangling.CNAME)
	}
}

func TestWildcardHostsAreNotLive(t *testing.T) {
	wildcardIP := "203.0.113.10"
	f := &fakeDNS{
		answers: map[string]*retryabledns.DNSData{
			"real.example.com": {Host: "real.example.com", A: []string{"93.184.216.34"}, StatusCode: "NOERROR"},
		},
		wildcards: map[string]*retryabledns.DNSData{
			"example.com": {A: []string{wildcardIP}, StatusCode: "NOERROR"},
		},
	}
	r := newResolver(t, "example.com", f)

	res, err := r.Resolve(context.Background(), []string{"real.example.com", "junk.example.com", "more.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	got := byHost(res.Hosts)
	if got["real.example.com"].Status != report.StatusLive {
		t.Errorf("real = %+v, want live: it has its own address", got["real.example.com"])
	}
	for _, h := range []string{"junk.example.com", "more.example.com"} {
		if got[h].Status != report.StatusWildcard {
			t.Errorf("%s = %+v, want wildcard", h, got[h])
		}
		// The host stays in the report, in its own bucket.
		if got[h].Addresses == nil {
			t.Errorf("%s lost its answer; a wildcard host is still reported", h)
		}
	}
	if len(res.Warnings) == 0 {
		t.Error("a detected wildcard must warn: it changes how the whole result reads")
	}
}

// A wildcard can sit on any label, not just the apex.
func TestWildcardIsDetectedOnIntermediateParents(t *testing.T) {
	f := &fakeDNS{
		wildcards: map[string]*retryabledns.DNSData{
			"dev.example.com": {A: []string{"203.0.113.20"}, StatusCode: "NOERROR"},
		},
		answers: map[string]*retryabledns.DNSData{
			"api.example.com": {Host: "api.example.com", A: []string{"93.184.216.34"}, StatusCode: "NOERROR"},
		},
	}
	r := newResolver(t, "example.com", f)

	res, err := r.Resolve(context.Background(), []string{"a.dev.example.com", "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	got := byHost(res.Hosts)
	if got["a.dev.example.com"].Status != report.StatusWildcard {
		t.Errorf("a.dev = %+v, want wildcard", got["a.dev.example.com"])
	}
	if got["api.example.com"].Status != report.StatusLive {
		t.Errorf("api = %+v, want live: the apex carries no wildcard", got["api.example.com"])
	}
}

// A host that answers with the wildcard address *and* one of its own is a
// real host that happens to share infrastructure.
func TestHostWithAnExtraAddressIsNotAWildcardArtifact(t *testing.T) {
	f := &fakeDNS{
		wildcards: map[string]*retryabledns.DNSData{
			"example.com": {A: []string{"203.0.113.10"}, StatusCode: "NOERROR"},
		},
		answers: map[string]*retryabledns.DNSData{
			"api.example.com": {Host: "api.example.com", A: []string{"203.0.113.10", "93.184.216.34"}, StatusCode: "NOERROR"},
		},
	}
	r := newResolver(t, "example.com", f)

	res, err := r.Resolve(context.Background(), []string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got := byHost(res.Hosts)["api.example.com"]; got.Status != report.StatusLive {
		t.Errorf("api = %+v, want live", got)
	}
}

// One flaky lookup must not condemn a whole branch as a wildcard.
func TestSingleFlakyProbeDoesNotCreateAWildcard(t *testing.T) {
	var once sync.Once
	f := &fakeDNS{answers: map[string]*retryabledns.DNSData{}}
	base := f.query
	r := newResolver(t, "example.com", f)
	r.query = func(host string) (*retryabledns.DNSData, error) {
		if strings.HasPrefix(host, "fr") {
			answered := false
			once.Do(func() { answered = true })
			if answered {
				return &retryabledns.DNSData{A: []string{"203.0.113.99"}, StatusCode: "NOERROR"}, nil
			}
			return &retryabledns.DNSData{StatusCode: "NXDOMAIN"}, nil
		}
		return base(host)
	}

	res, err := r.Resolve(context.Background(), []string{"a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got := byHost(res.Hosts)["a.example.com"]; got.Status == report.StatusWildcard {
		t.Error("a single answering probe out of three must not establish a wildcard")
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}
}

func TestResolveReportsUnresolvedHostsWhenOutOfTime(t *testing.T) {
	f := &fakeDNS{}
	r := newResolver(t, "example.com", f)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := r.Resolve(ctx, []string{"a.example.com", "b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("a resolution that never ran must report itself truncated")
	}
	for _, h := range res.Hosts {
		if h.Status != report.StatusDiscovered {
			t.Errorf("%s = %q, want discovered rather than an invented verdict", h.Host, h.Status)
		}
	}
}

func TestParentsOf(t *testing.T) {
	cases := map[string][]string{
		"a.b.example.com": {"b.example.com", "example.com"},
		"www.example.com": {"example.com"},
		"example.com":     nil,
		"com":             nil,
	}
	for host, want := range cases {
		got := parentsOf(host)
		if !slices.Equal(got, want) {
			t.Errorf("parentsOf(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestCandidateParentsStaysInScope(t *testing.T) {
	got, unprobed := candidateParents([]string{"a.dev.example.com", "www.example.com", "evil.other.net"}, "example.com")
	if unprobed != 0 {
		t.Errorf("candidateParents dropped %d zones, want 0: the cap must not bite on a small list", unprobed)
	}
	slices.Sort(got)
	want := []string{"dev.example.com", "example.com"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("candidateParents = %v, want %v: out-of-scope parents must not be probed", got, want)
	}
}

func TestCandidateParentsProbesRootFirst(t *testing.T) {
	got, _ := candidateParents([]string{"a.dev.example.com"}, "example.com")
	if len(got) == 0 || got[0] != "example.com" {
		t.Fatalf("candidateParents = %v, want the root first: a wildcard there voids the whole run", got)
	}
}

// The cap keeps the zones holding the most hosts, and says how many it left
// out. A run that silently probed 500 of 3000 zones would report a narrowed
// wildcard check as an exhaustive one.
func TestCandidateParentsCapsByCoverage(t *testing.T) {
	var hosts []string
	for i := range 600 {
		// zone-0 gets three hosts, every other zone gets one, so the ranking
		// is unambiguous and the tie-break is exercised by the rest.
		zone := fmt.Sprintf("z%03d.example.com", i)
		hosts = append(hosts, "a."+zone)
		if i == 0 {
			hosts = append(hosts, "b."+zone, "c."+zone)
		}
	}

	got, unprobed := candidateParents(hosts, "example.com")
	if len(got) != maxWildcardParents {
		t.Errorf("candidateParents returned %d zones, want the cap of %d", len(got), maxWildcardParents)
	}
	if want := 600 - (maxWildcardParents - 1); unprobed != want {
		t.Errorf("unprobed = %d, want %d", unprobed, want)
	}
	if got[0] != "example.com" {
		t.Errorf("got[0] = %q, want the root", got[0])
	}
	if got[1] != "z000.example.com" {
		t.Errorf("got[1] = %q, want the most-covering zone z000.example.com", got[1])
	}
	if slices.Contains(got, "z599.example.com") {
		t.Error("the cap kept a least-covering zone and must have dropped it")
	}
}

// An empty domain is valid: targets mode has no root.
func TestNewAcceptsAnEmptyDomain(t *testing.T) {
	if _, err := New(Options{Concurrency: 1, Timeout: time.Second, WildcardProbes: 1, Logger: discardLogger()}); err != nil {
		t.Errorf("New rejected a targets-mode configuration: %v", err)
	}
}

func TestNewRejectsUnusableOptions(t *testing.T) {
	base := Options{Domain: "example.com", Concurrency: 1, Timeout: time.Second, WildcardProbes: 1, Logger: discardLogger()}
	for name, mutate := range map[string]func(*Options){
		"no logger":      func(o *Options) { o.Logger = nil },
		"no concurrency": func(o *Options) { o.Concurrency = 0 },
		"no timeout":     func(o *Options) { o.Timeout = 0 },
		"no probes":      func(o *Options) { o.WildcardProbes = 0 },
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

// With no root — targets mode — parents come from the host list alone, and an
// empty string must never become a candidate.
func TestCandidateParentsWithoutARoot(t *testing.T) {
	got, unprobed := candidateParents([]string{"a.dev.example.com", "www.other.net"}, "")
	if unprobed != 0 {
		t.Errorf("unprobed = %d, want 0", unprobed)
	}
	slices.Sort(got)
	want := []string{"dev.example.com", "example.com", "other.net"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("candidateParents = %v, want %v", got, want)
	}
	for _, p := range got {
		if p == "" {
			t.Error("the empty string was queued as a parent to probe")
		}
	}
}

// A verification list legitimately spans several apexes of one perimeter.
func TestWildcardDetectionSpansSeveralApexes(t *testing.T) {
	f := &fakeDNS{
		wildcards: map[string]*retryabledns.DNSData{
			"dev.example.com": {A: []string{"203.0.113.30"}, StatusCode: "NOERROR"},
		},
		answers: map[string]*retryabledns.DNSData{
			"www.other.net": {Host: "www.other.net", A: []string{"93.184.216.34"}, StatusCode: "NOERROR"},
		},
	}
	r := newResolver(t, "", f)

	res, err := r.Resolve(context.Background(), []string{"a.dev.example.com", "www.other.net"})
	if err != nil {
		t.Fatal(err)
	}
	got := byHost(res.Hosts)
	if got["a.dev.example.com"].Status != report.StatusWildcard {
		t.Errorf("a.dev = %+v, want wildcard", got["a.dev.example.com"])
	}
	if got["www.other.net"].Status != report.StatusLive {
		t.Errorf("other.net host = %+v, want live: a different apex is still in scope", got["www.other.net"])
	}
}
