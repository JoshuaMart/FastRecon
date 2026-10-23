# 03 — Output

## Formats

| `--format` | |
|---|---|
| `json` | one indented document; the default |
| `json-compact` | the same document on one line, for log sinks |
| `jsonl` | one host per line, for large scopes — without the run metadata, sources or warnings |
| `text` | human-readable summary |

## Sinks

Sinks are independent and can be combined.

**stdout** (default) — the full document. All logging goes to stderr, so `fastrecon … | jq`
works.

**file** — `--output ./results/report.json`. Parent directories are created; the write is
atomic (temp file + rename) with mode `0600`, since a report is reconnaissance on whoever it
describes. Non-regular destinations (`/dev/stdout`, named pipes) are written directly.

**webhook** — `--webhook-url`. The full report as raw JSON (`Content-Type:
application/json`), the same bytes as the other sinks. Options: `--webhook-method` (default
`POST`), `--webhook-header` (repeatable, for auth), `--webhook-timeout`, `--webhook-retries`.

- 5xx, 429 and transport errors are retried with exponential backoff and jitter, honouring
  `Retry-After`; the total wait is capped. Other 4xx are not retried: the request itself is
  wrong.
- **Redirects are not followed.** Following a 301/302 would turn the POST into a GET without
  the report — and count it as delivered. Point `--webhook-url` at the final address.
- The response body is drained but never logged: a target may echo the payload back.

A failed delivery sets a non-zero exit code but does not discard the other sinks' output.
Delivery runs on its own context, bounded by the `--output-margin` share, so a run stopped by
a signal still delivers its partial report.

Logs are for *reading* a run, not a transport: a collector may split long lines (Scaleway
Cockpit cuts at 16 KiB). Anything a machine consumes should go to the webhook.

## Report shape

```json
{
  "schema_version": "1.1",
  "run": {
    "id": "01J...",
    "domain": "example.com",
    "input": "domain",
    "scope": "full",
    "stages": ["enumerate", "exclude", "resolve", "portscan", "httpprobe"],
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:07:12Z",
    "duration_ms": 432000,
    "completed": true,
    "truncated_by_timeout": false,
    "version": "1.2.3",
    "environment": "serverless-job",
    "degraded": ["resolvers_unvalidated"]
  },
  "sources": [
    {"name": "chaos", "status": "ok", "found": 812, "duration_ms": 1400},
    {"name": "securitytrails", "status": "skipped_no_key", "found": 0},
    {"name": "c99", "status": "rate_limited", "found": 0, "error": "unexpected status code 429"}
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
      "sources": ["chaos", "crt"],
      "cdn": [{"name": "cloudflare", "type": "waf",
               "addresses": ["93.184.216.34"], "scan_limited": true}],
      "scan": {"scanned": 2, "open": 1, "refused": 1, "filtered": 0, "unknown": 0},
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
           "tech": ["HSTS", "Nginx"],
           "tls": {"subject_cn": "*.example.com", "issuer": "R3",
                   "not_after": "2026-06-01T00:00:00Z",
                   "sans": ["api.example.com", "www.example.com"],
                   "cert_spki_hash": "9f86d0…"}
         }}
      ]
    },
    {"host": "old.example.com", "status": "dead", "reason": "nxdomain", "sources": ["crt"]}
  ],
  "excluded": [{"host": "admin.example.com", "pattern": "admin.example.com"}],
  "warnings": ["source c99: unexpected status code 429", "exclusion pattern \"*.qa.example.com\" matched nothing"]
}
```

A host carries the status of the furthest stage that reached it: `discovered`, `live`,
`dead` or `wildcard`. In an `enum` scope every host is `discovered`.

## Reading a report

**Dead hosts stay in.** A dangling CNAME is a finding, so the alias is kept with the verdict.
`nxdomain` (the name does not exist) and `no_answer` (it exists, with no address) are
distinct.

**A host is never declared dead without an answer.** One the resolve stage did not reach
before its deadline stays `discovered`; so does one whose resolver failed (SERVFAIL,
REFUSED), with the reason `resolver_error` and a warning counting them.

**Every source appears**, successful or not, and each host lists the sources that returned
it, sorted so two runs compare equal.

**`scan` says what the sweep attempted**: `scanned` = `open` + `refused` + `filtered` +
`unknown`. Only a connection the target turned down is `refused`; `unknown` is a probe that
says nothing about the port — a local limit, or no route from the scanner (an IPv6 address
on a runner without IPv6). A probe in flight when the run ends is not counted. The field is
**absent** when the scan did not run, so "nothing listening" and "never probed" never look
alike.

**`scan_limited` marks a narrowed sweep**: a CDN or WAF address scanned on 80 and 443 only.
Without it, "only 80 and 443 are open" would read like a minimal host.

**Each port lists the addresses it was found open on**, so one service behind ten names is
distinguishable from ten services.

**Wildcard hosts are kept**, marked `wildcard` and out of the live set. A real host
resolving to exactly the wildcard's addresses is indistinguishable at the DNS level, and a
consumer can reclassify kept data but not deleted data.

**`url` matches the probed scheme and port**, omitting the port when it is the scheme's
default — so TLS answering on port 80 stands out. Where redirects led goes in `final_url`; a
chain that breaks on a later hop still reports its first hop, marked `redirect_unfollowed`.

**`tls` is the probed endpoint's certificate**: taken from the first hop of a TLS
connection, never from wherever a redirect led.

**A truncated run is still a valid report.** `completed: false` with
`truncated_by_timeout: true` ran out of time; `completed: false` alone was stopped on
purpose. A consumer may retry the first, not the second.

## Degraded conditions

`run.degraded` carries machine-readable codes for conditions that narrowed a run. It runs
alongside `warnings`, which is prose for humans and can change wording.

| Code | Condition |
|---|---|
| `resolvers_unvalidated` | some or all of the pool was used without validation — the health budget ran out, or every resolver failed the check and the run continued anyway |
| `wildcard_zones_capped` | more zones held hosts than the run could probe for a wildcard |

## Exit codes

| Code | Meaning | Retry? |
|---|---|---|
| 0 | run completed, report emitted | — |
| 1 | invalid configuration or usage | no, it will fail identically |
| 2 | report emitted, scope unfinished | no, the report was delivered |
| 3 | report produced, a destination failed | no, same reason |
| 4 | no report produced, including transient failures | yes |

Only code 4 justifies a retry, so a platform that retries on any non-zero exit re-runs jobs
that already delivered — see [Retries: leave them off](04-deployment.md#retries-leave-them-off).
`serve` makes the same split: a transient failure is a `500`, a caller mistake a `400`.

## Logging

Logs go to **stderr**, structured JSON by default (`--log-format=text` for humans). Each
stage logs its counts and duration at `info`, per-host detail is at `debug`, and a final
line carries the same counters as `stats` — so a run is legible even when the report went to
a webhook. No credential, and no URL containing one, appears in a log line.
