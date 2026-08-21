// Package report defines the run report: the single document every sink emits.
//
// There is one shape, versioned by SchemaVersion, for every consumer. A change
// that removes or repurposes a field is a schema version bump.
package report

import (
	"time"

	"github.com/JoshuaMart/FastRecon/internal/stage"
)

// SchemaVersion identifies the report contract.
// Minor bumps are additive: fields appear, none are removed or repurposed.
const SchemaVersion = "1.1"

// Host status values.
const (
	// StatusDiscovered is a host found by enumeration and kept by the
	// exclusion filter, but not yet resolved. It is what every host in an
	// enumeration-only run looks like.
	StatusDiscovered = "discovered"
	StatusLive       = "live"
	StatusDead       = "dead"
	StatusWildcard   = "wildcard"
)

// Source status values.
const (
	SourceOK           = "ok"
	SourceSkippedNoKey = "skipped_no_key"
	SourceSkipped      = "skipped"
	SourceError        = "error"
	SourceTimeout      = "timeout"
	SourceRateLimited  = "rate_limited"
)

// Reasons a host ended up in the dead bucket.
const (
	ReasonNXDomain = "nxdomain"
	ReasonNoAnswer = "no_answer"
	ReasonTimeout  = "timeout"
	ReasonWildcard = "wildcard"
)

// Report is the complete output of one run.
type Report struct {
	SchemaVersion string     `json:"schema_version"`
	Run           Run        `json:"run"`
	Sources       []Source   `json:"sources"`
	Stats         Stats      `json:"stats"`
	Hosts         []Host     `json:"hosts"`
	Excluded      []Excluded `json:"excluded,omitempty"`
	Warnings      []string   `json:"warnings,omitempty"`
}

// Degraded codes. Machine-readable twins of the prose in Warnings.
const (
	// DegradedResolversUnvalidated: the health budget ran out, so part of the
	// pool was used without being checked.
	DegradedResolversUnvalidated = "resolvers_unvalidated"
	// DegradedWildcardZonesCapped: more zones held hosts than the run could
	// probe for a wildcard record.
	DegradedWildcardZonesCapped = "wildcard_zones_capped"
)

// Input tells what stage 1 was fed.
const (
	InputDomain  = "domain"
	InputTargets = "targets"
)

// Run holds the metadata of the execution itself.
type Run struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// Input is "domain" or "targets". A consumer needs it to know what a
	// missing host means: enumeration is authoritative on presence, never on
	// absence.
	Input    string    `json:"input"`
	Scope    string    `json:"scope"`
	Stages   []string  `json:"stages"`
	Started  time.Time `json:"started_at"`
	Finished time.Time `json:"finished_at"`
	Duration int64     `json:"duration_ms"`
	// Completed is false when a stage was cut short or failed outright. The
	// report is still emitted and still valid — it is just not exhaustive.
	Completed          bool   `json:"completed"`
	TruncatedByTimeout bool   `json:"truncated_by_timeout"`
	Version            string `json:"version"`
	Environment        string `json:"environment"`
	// Degraded lists machine-readable codes for conditions that narrowed the
	// run. It runs parallel to Warnings, which is prose for a human: matching
	// on prose stops working the day the wording changes.
	Degraded []string `json:"degraded,omitempty"`
}

// Source records what one enumeration source contributed and how it went. A
// source that silently returns nothing is a bug worth seeing, so every source
// appears here whether it succeeded or not.
type Source struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Found    int    `json:"found"`
	Duration int64  `json:"duration_ms,omitempty"`
	// Partial marks results kept from a source that was abandoned mid-way,
	// typically after exhausting its rate-limit budget.
	Partial bool   `json:"partial,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Stats are the run counters, also emitted as the final log line so a run is
// legible in a log-only environment.
type Stats struct {
	Enumerated   int `json:"enumerated"`
	Excluded     int `json:"excluded"`
	InScope      int `json:"in_scope"`
	Live         int `json:"live"`
	Dead         int `json:"dead"`
	Wildcard     int `json:"wildcard"`
	OpenPorts    int `json:"open_ports"`
	HTTPServices int `json:"http_services"`
}

// Host is one discovered subdomain and everything learned about it.
type Host struct {
	Host      string   `json:"host"`
	Status    string   `json:"status"`
	Addresses []string `json:"addresses,omitempty"`
	CNAME     []string `json:"cname,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	// Sources are the enumeration sources that returned this host, sorted so
	// two runs of the same perimeter compare equal. Absent in targets mode.
	Sources []string `json:"sources,omitempty"`
	CDN     []CDN    `json:"cdn,omitempty"`
	// Scan accounts for what the port sweep attempted on this host. Absent
	// when the stage did not run: a zeroed object would read as a sweep that
	// tried and found nothing, which is a different claim.
	Scan  *Scan  `json:"scan,omitempty"`
	Ports []Port `json:"ports,omitempty"`
}

// CDN records that some of a host's addresses sit behind a CDN, WAF or cloud
// edge. It is populated whether or not the scan was restricted: a port list
// narrowed to 80 and 443 is indistinguishable from a genuinely minimal host
// unless the report says the narrowing was deliberate.
type CDN struct {
	Name string `json:"name"`
	// Type is the kind of provider matched: cdn, waf or cloud.
	Type string `json:"type,omitempty"`
	// Addresses are the host addresses this provider matched. A host can have
	// a CDN address and an origin address at once.
	Addresses []string `json:"addresses,omitempty"`
	// ScanLimited marks a port list restricted to the standard web ports
	// because of this provider.
	ScanLimited bool `json:"scan_limited"`
}

// Scan is the per-host outcome of the port sweep.
//
// Without it, a host with nothing listening and a host that was never probed
// produce the same document — as do a host that closed everything and one
// behind a firewall that started dropping. Open, Refused, Filtered and Unknown
// always sum to Scanned.
type Scan struct {
	// Scanned is what was attempted, so a host narrowed to the web ports by
	// scan_limited counts those, not the full selection.
	Scanned  int `json:"scanned"`
	Open     int `json:"open"`
	Refused  int `json:"refused"`
	Filtered int `json:"filtered"`
	// Unknown is a probe that failed on a local limit. It says nothing about
	// the target, so it is neither of the two above.
	Unknown int `json:"unknown"`
}

// Port is an open port on a host, with the HTTP service behind it if any.
type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	// Addresses are where this port was found open. An address is scanned
	// once and its result mapped onto every host resolving to it, so without
	// this a consumer cannot tell one service behind ten names from ten
	// services — the two look identical in the host list.
	Addresses []string `json:"addresses,omitempty"`
	HTTP      *HTTP    `json:"http,omitempty"`
}

// HTTP describes the service answering on a port, with the scheme that
// actually worked rather than one assumed from the port number.
type HTTP struct {
	// URL is the URL that was probed. It always matches Scheme and the port,
	// so it identifies this service rather than wherever it redirects to.
	URL string `json:"url"`
	// FinalURL is where the redirects landed, when they went anywhere else.
	FinalURL      string   `json:"final_url,omitempty"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	ResponseTime  int64    `json:"response_time_ms,omitempty"`
	Server        string   `json:"server,omitempty"`
	Redirects     []string `json:"redirects,omitempty"`
	// RedirectUnfollowed marks a service whose redirect target could not be
	// reached. The response recorded here is the first hop, which is a real
	// finding even though the chain is broken.
	RedirectUnfollowed bool     `json:"redirect_unfollowed,omitempty"`
	Tech               []string `json:"tech,omitempty"`
	TLS                *TLS     `json:"tls,omitempty"`
}

// TLS is the certificate seen on an HTTPS service. SANs may name hosts the
// enumeration missed; they are recorded, not fed back into the pipeline.
type TLS struct {
	SubjectCN string    `json:"subject_cn,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	SANs      []string  `json:"sans,omitempty"`
	// CertSPKIHash is the lowercase hex SHA-256 of the certificate's
	// SubjectPublicKeyInfo. It survives renewal when the key is reused, which
	// is what makes it a pivot; the certificate fingerprint does not.
	CertSPKIHash string `json:"cert_spki_hash,omitempty"`
}

// Excluded records a host dropped by an exclusion pattern, with the pattern
// responsible — needed to debug an over-broad exclusion.
type Excluded struct {
	Host    string `json:"host"`
	Pattern string `json:"pattern"`
}

// New starts a report for a run.
func New(id, domain, input string, scope stage.Scope, version, environment string, started time.Time) *Report {
	return &Report{
		SchemaVersion: SchemaVersion,
		Run: Run{
			ID:          id,
			Domain:      domain,
			Input:       input,
			Scope:       scope.String(),
			Stages:      scope.StageNames(),
			Started:     started.UTC(),
			Completed:   true,
			Version:     version,
			Environment: environment,
		},
		Sources: []Source{},
		Hosts:   []Host{},
	}
}

// Warnf appends a warning. Warnings are part of the report, not just the log:
// a consumer must be able to tell a clean run from a degraded one.
func (r *Report) Warnf(format string, args ...any) {
	r.Warnings = append(r.Warnings, sprintf(format, args...))
}

// Finish stamps the end of the run and recomputes the counters.
func (r *Report) Finish(finished time.Time) {
	r.Run.Finished = finished.UTC()
	r.Run.Duration = finished.Sub(r.Run.Started).Milliseconds()
	r.recount()
}

// recount derives the per-host counters from Hosts. Enumerated, Excluded and
// InScope describe stages that happen before the host list exists, so they are
// set by the pipeline and left alone here.
func (r *Report) recount() {
	r.Stats.Live, r.Stats.Dead, r.Stats.Wildcard = 0, 0, 0
	r.Stats.OpenPorts, r.Stats.HTTPServices = 0, 0
	for _, h := range r.Hosts {
		switch h.Status {
		case StatusLive:
			r.Stats.Live++
		case StatusWildcard:
			r.Stats.Wildcard++
		case StatusDead:
			r.Stats.Dead++
		}
		for _, p := range h.Ports {
			r.Stats.OpenPorts++
			if p.HTTP != nil {
				r.Stats.HTTPServices++
			}
		}
	}
}
