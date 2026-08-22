# 03 — Output

## Formats

| `--format` | |
|---|---|
| `json` | one indented document; the default |
| `json-compact` | the same document on one line, for log sinks |
| `jsonl` | one host per line, for large scopes |
| `text` | human-readable summary |

`jsonl` is not the middle ground it looks like: it emits only hosts, dropping the run
metadata, the per-source accounting and the warnings.

Logs are a place to *read* a run, not a transport — a collector may split long lines
(Scaleway Cockpit cuts at 16 KiB). Anything a machine consumes should go to `--webhook-url`.

## Sinks

Sinks are independent and can be combined in a single run.

**stdout** (default) — the full document. When stdout is a sink, *all* logging goes to
stderr so stdout stays parseable; that is what makes `fastrecon … | jq` work and keeps a
job's logs readable.

**file** — `--output ./results/report.json`. Parent directories are created as needed.
Written atomically (temp file + rename) so a consumer never reads a half-written report, and
with mode `0600`: a report names hosts, open ports and certificates, which is reconnaissance
on whoever it describes if the path is shared. Destinations that are not regular files —
`/dev/stdout`, `/dev/null`, named pipes — are written through directly, since there is
nothing to make atomic.

**webhook** — `--webhook-url`. An HTTP POST of the full report as raw JSON
(`Content-Type: application/json`), unchanged from what the other sinks emit. The target is
an internal API, not a chat destination, so there is no message formatting and no summary
variant: one shape for every consumer. Options: `--webhook-method` (default `POST`),
`--webhook-header` (repeatable, for auth), `--webhook-timeout`, `--webhook-retries`.

Retries cover 5xx, 429 and transport errors, with exponential backoff plus jitter so several
jobs retrying do not synchronise. A `Retry-After` header is honoured over the computed wait
— the endpoint knows better than the schedule — and the total wait is capped so a long chain
cannot outlive its budget. **Every other 4xx is not retried**: the request itself is wrong,
most often the credentials or the URL, and repeating it only delays the error. The response
body is drained but never logged, since a webhook target may echo the payload back and
re-logging it would undo the redaction applied upstream.

A delivery failure sets a non-zero exit code but does **not** discard the other sinks'
output.

**Delivery is detached from the run.** It runs on its own context, derived from
`context.WithoutCancel` and bounded by the share of the budget reserved by
`--output-margin`. A stopped job arrives as a signal that cancels the run's context — and
the entire point of catching that signal is that the partial report still reaches its
destinations, which delivering on the cancelled context would prevent.

## Report shape

```json
{
  "schema_version": "1.0",
  "run": {
    "id": "01J...",
    "domain": "example.com",
    "stages": ["enumerate", "exclude", "resolve", "portscan", "httpprobe"],
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:07:12Z",
    "duration_ms": 432000,
    "completed": true,
    "truncated_by_timeout": false,
    "version": "1.2.3",
    "environment": "serverless-job"
  },
  "sources": [
    {"name": "chaos", "status": "ok", "found": 812, "duration_ms": 1400},
    {"name": "securitytrails", "status": "skipped_no_key", "found": 0},
    {"name": "c99", "status": "error", "found": 0, "error": "rate limited"}
  ],
  "stats": {
    "enumerated": 1204, "excluded": 37, "in_scope": 1167,
    "live": 480, "dead": 671, "wildcard": 16,
    "open_ports": 913, "http_services": 604
  },
  "hosts": [
    {
      "host": "api.example.com",
      "status": "live",
      "addresses": ["93.184.216.34"],
      "cname": ["edge.example.net"],
      "cdn": [{"name": "cloudflare", "type": "waf",
               "addresses": ["93.184.216.34"], "scan_limited": true}],
      "ports": [
        {"port": 443, "protocol": "tcp", "state": "open",
         "addresses": ["93.184.216.34"],
         "http": {
           "url": "https://api.example.com",
           "final_url": "https://api.example.com/v2",
           "scheme": "https",
           "status_code": 200,
           "title": "API",
           "content_length": 1533,
           "response_time_ms": 251,
           "server": "nginx",
           "redirects": ["https://api.example.com"],
           "redirect_unfollowed": false,
           "tech": ["nginx", "HSTS"],
           "tls": {"subject_cn": "*.example.com", "issuer": "R3",
                   "not_after": "2026-06-01T00:00:00Z",
                   "sans": ["api.example.com", "www.example.com"]}
         }}
      ]
    },
    {"host": "old.example.com", "status": "dead", "reason": "nxdomain"}
  ],
  "excluded": [{"host": "admin.example.com", "pattern": "admin.*"}],
  "warnings": ["source c99 rate limited", "exclusion pattern '*.qa.example.com' matched nothing"]
}
```

A host carries the status of the furthest stage that reached it. In an `enum` scope nothing
is resolved, so every surviving host is `discovered`: the enumeration result is data in its
own right and must appear in the report, not merely be counted in `stats`.

## Reading a report

A few things the report is deliberate about, because they change how you read it.

**Dead hosts stay in.** A dangling CNAME is a finding, not noise, so the alias target is
kept alongside the verdict. `nxdomain` and `no_answer` are distinct: a name that exists but
has no address (MX or TXT records only) is not a name that does not exist. A host the
resolve stage never reached before its deadline is reported as `discovered`, not as dead —
inventing a verdict for a host that was never queried would be worse than admitting the gap.

**Every source appears**, successful or not. A source that silently returns nothing is
exactly what that accounting exists to expose. Each host also records the sources that
returned it, sorted — sorting is not cosmetic: a consumer deduplicating observations by
comparing payloads would be defeated by a set that came back in a different order every run.

**`scan_limited` marks a narrowed sweep.** "Only 80 and 443 are open" is indistinguishable
from a genuinely minimal host unless the report says the scan was narrowed on purpose. Every
host behind a CDN carries the provider name and this marker.

**Each host says what its sweep attempted**, in `scan`: `scanned` plus `open`, `refused`,
`filtered` and `unknown`, which always sum to it. Without them a report says the same thing
for opposite findings — a host with nothing listening and a host that was never probed both
show an empty port list. `scanned` counts what was *attempted*, so a host narrowed by
`scan_limited` counts those ports, not the full selection. `unknown` is a probe that failed
on a local limit (file descriptors, mostly): it says nothing about the target, so folding it
into `refused` or `filtered` would make "everything refused" true over ports that were never
tried. The field is **absent** when the scan did not run — a zeroed object would read as a
sweep that tried and found nothing, a different claim.

**Each port records the addresses it was found open on.** Without that, one service behind
ten CNAMEs is indistinguishable from ten services.

**Wildcard hosts are kept.** They are marked `wildcard` and excluded from the live set, but
they stay in the report with their answers: a genuine host resolving to exactly the
wildcard's addresses is indistinguishable from an artifact at the DNS level, and the
classification is recoverable by a consumer while deleted data is not.

**`url` always matches the probed scheme and port**, and omits the port when it is the
scheme's default. That makes a scheme on a non-default port the only kind that keeps its
port, so an unusual finding — TLS answering on port 80, observed in practice — stands out.
Where the redirects landed goes in `final_url`. A broken redirect chain still reports its
first hop, marked `redirect_unfollowed`.

**A TLS certificate is recorded only for a connection that was itself TLS**, so a plain-HTTP
probe that redirects to an HTTPS host cannot attach that other endpoint's certificate to
this port.

**A truncated run is still a valid report.** `completed: false` plus
`truncated_by_timeout: true` is a deadline-truncated run. An operator stopping the job is
reported differently — `completed: false` with `truncated_by_timeout` left **false** — since
a consumer may reasonably retry a run that ran out of time, and must not retry one somebody
stopped on purpose.

## Degraded conditions

`run.degraded` carries machine-readable codes for conditions that narrowed a run, or that
make part of its output unsafe to conclude from.

| Code | Condition |
|---|---|
| `resolvers_unvalidated` | some or all of the pool was used without being validated — the health budget ran out, or every resolver failed the check and the run continued anyway |
| `wildcard_zones_capped` | more zones held hosts than the run could probe for a wildcard |

It runs **parallel to `warnings`**, which stays prose for a human. Matching on prose works
until the wording changes and then stops silently — the failure mode this field exists to
remove. Neither replaces the other.

## Exit codes

| Code | Meaning | Retry? |
|---|---|---|
| 0 | run completed, report emitted | — |
| 1 | invalid configuration or usage | no, it will fail identically |
| 2 | report emitted, scope unfinished | no, the report was delivered |
| 3 | report produced, a destination failed | no, same reason |
| 4 | no report produced, including transient failures | yes |

Only code 4 justifies a retry. A platform that retries on any non-zero exit will re-run jobs
that already delivered their report, so leave retries off unless duplicates are acceptable —
see [Retries: leave them off](04-deployment.md#retries-leave-them-off).

They are distinct because a job scheduler's only signal is the exit status. A network blip
reported as `1` is something no scheduler will ever retry, and a truncated run reported as
`0` would be a silent lie about completeness. The split runs deeper than the table: a
preparation failure is either transient — an unreachable resolver list, for instance — and
therefore ours, or a mistake in the configuration and therefore the caller's. The HTTP
handler makes the same split into `500` and `400`.

## Logging

All logs go to **stderr**, structured JSON by default (`--log-format=text` for humans),
keeping stdout clean for the report. Per-stage progress lines with counts and durations at
`info`, per-host detail at `debug`, and a final summary line carrying the same counters as
`stats` — so the run outcome is visible in a log-only environment even when the report
itself went to a webhook.

No credential and no full request URL containing a key ever appears in a log line.
