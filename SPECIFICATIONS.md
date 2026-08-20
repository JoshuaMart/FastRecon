# FastRecon — Specifications

> Status: draft v0.1 — design document, no implementation yet.

## 1. Overview

FastRecon is a single-binary attack-surface discovery tool. Given a root domain and an
exclusion list, it enumerates subdomains from multiple passive sources, filters out
excluded hosts, separates live hosts from dead ones, optionally scans ports, and probes
the discovered ports for HTTP services.

It is designed to run identically in four environments:

- as a local CLI binary,
- inside a Docker container,
- as a serverless job (primary target: Scaleway Serverless Jobs),
- as a serverless function (container-based, primary target: Scaleway Serverless Functions).

The same artifact — one container image, one binary — serves all four. There is no separate
"serverless build". The binary exposes two entrypoints: the default one-shot CLI run, and a
`serve` subcommand that turns the same pipeline into an HTTP handler for the function
deployment.

## 2. Goals

- One static binary with no runtime dependency on external tools. This is the target, not a
  hard constraint: shelling out to an external binary is acceptable where it buys something
  real, as long as the default container image stays self-contained.
- Runs unprivileged: no root, no `CAP_NET_RAW`, no raw sockets required on the default path.
- Fully configurable via CLI flags **and** environment variables (serverless jobs configure
  through env vars and args).
- Zero secrets baked into the container image — the image is built by CI and is public-safe.
- Selectable pipeline stages: enumeration only, enumeration + ports, or full.
- Machine-readable output (JSON) usable by downstream tooling.
- Stateless: every run is self-contained and produces a complete report. No database, no
  cross-run diffing inside the tool.

## 3. Stack decision

**Go (1.23+).**

Rationale — this is not a preference, it is what makes the rest of the spec cheap:

- Every tool in the target pipeline is Go and is importable as a library:
  `subfaster` (enumeration), `dnsx` (resolution), `naabu` (port scan), `httpx` (HTTP probe).
  Using them as packages removes the need to ship and exec external binaries, which is the
  main source of pain in serverless (no package manager, read-only or ephemeral filesystem,
  binary size, PATH assumptions).
- Cross-compiles to a fully static binary → `FROM scratch`/distroless image, small pull,
  fast job cold start.
- Native concurrency model fits a fan-out pipeline (thousands of DNS resolutions and TCP
  connects).

Consequence: the deliverable is a Go module exposing both a `cmd/fastrecon` CLI and an
internal pipeline package, so the pipeline can later be driven from an HTTP handler or a
queue consumer without restructuring.

## 4. Execution environments

| | Local CLI | Docker (local) | Serverless Job | Serverless Function |
|---|---|---|---|---|
| Invocation | `fastrecon -d example.com` | `docker run ... fastrecon -d ...` | job definition: image + args + env | HTTP request to `fastrecon serve` |
| Config source | flags, env, config file | flags, env, mounted config file | env vars + startup args | env vars + per-request JSON body |
| Secrets | env / config file / keychain | env / mounted file | job env vars | function env vars / Secret Manager |
| stdout JSON | read directly | read directly | captured as logs (Cockpit) — readable, but not machine-retrievable | logs only; the report goes in the HTTP response |
| Result delivery | stdout / file | stdout / mounted volume file | **webhook** (primary), stdout for inspection | **HTTP response** (primary), webhook optional |
| Privileges | can be root if the user wants | can add `--cap-add=NET_RAW` | assume unprivileged, no capabilities | assume unprivileged, no capabilities |
| Time budget | unbounded | unbounded | the job's configured timeout | the function's hard timeout — the tightest of the four |
| Realistic scope | any | any | any, up to the job timeout | `enum` / `resolve` on bounded scopes |

### 4.1 Serverless constraints that shape the design

- **No root, no raw sockets.** `masscan` and `naabu`'s SYN mode are unavailable. The default
  port-scan mode is TCP **connect** scanning, which works unprivileged. SYN mode is an opt-in
  flag that is only expected to work locally with `--cap-add=NET_RAW`; the tool must detect
  the missing capability and fail with a clear message rather than silently returning zero ports.
- **stdout is logs, not a return value.** A serverless job's stdout goes to the platform log
  pipeline. It is fine for humans and for debugging, and it is the default output because it
  is the one thing that works everywhere — but a job that must hand results to another system
  uses the webhook sink. This is why the sinks are independent and combinable.
- **Ephemeral, possibly read-only filesystem.** Nothing is written outside the configured
  output path and `$TMPDIR`. No implicit writes to `$HOME` (relevant: subfinder/subfaster
  default to `$HOME/.config/...` — FastRecon must pass provider config explicitly instead of
  relying on that default).
- **Bounded run time.** The tool takes a global deadline (`--timeout`) and must return a
  partial, well-formed report when it expires rather than being killed mid-flight. Each stage
  gets its own budget derived from the global one.
- **No inbound network (job).** A job is push-only; nothing listens. A function is the
  opposite — it exists to be called — which is why the HTTP entrypoint is a separate
  subcommand rather than always-on behaviour.

### 4.2 Serverless function specifics

The function deployment is **container-based**: the same image, started with `serve` instead
of a one-shot run. This keeps a single artifact and a single code path — the handler builds a
run configuration and calls the same pipeline the CLI calls.

- **The function's timeout is the binding constraint.** It is materially shorter than a job's,
  and a full five-stage run over a large scope will not fit. The function is intended for
  `enum` and `resolve` scopes; `ports` and `full` are permitted but the caller owns the risk.
  The tool does not silently downgrade the requested stages — it runs what was asked and
  returns a truncated report if the deadline hits.
- **The deadline is derived, not assumed.** On startup the handler resolves its budget from,
  in order: an explicit `timeout` in the request body, `FASTRECON_TIMEOUT`, or a platform-
  provided remaining-time value when one is available. It reserves a margin (default 10%) to
  serialize and return the report, so the caller always receives a well-formed document
  instead of a platform-level timeout error.
- **No work after the response.** On most FaaS platforms the instance is frozen or reclaimed
  once the handler returns, so "respond 202 immediately, finish in the background, POST to a
  webhook later" is not reliable. The function therefore runs **synchronously** and returns
  the report in the response body. Work that cannot fit in a function timeout belongs in a
  job — that is the split between the two deployments, and the documentation must say so
  plainly rather than offering a fire-and-forget mode that intermittently loses runs.
- **Concurrency and reuse.** The process must be safe for sequential reuse across invocations
  on a warm instance: no global mutable state between runs, and all per-run resources
  (resolver pools, HTTP clients, goroutines) torn down when the run ends. Each run gets its
  own context and its own cancellation.
- **Authentication.** The handler requires a shared token (`--api-token` /
  `FASTRECON_API_TOKEN`) compared in constant time, in addition to whatever the platform
  provides. An unauthenticated subdomain-enumeration endpoint is an open relay for someone
  else's recon and burns your API quotas.

#### Request and response

```
POST /run
Authorization: Bearer <token>

{
  "domain": "example.com",
  "exclude": ["*.dev.example.com", "re:^staging[0-9]*\\."],
  "stages": "enum",
  "ports": "top-100",
  "timeout": "300s",
  "webhook_url": "https://internal.example.net/hooks/recon"
}
```

The response body is the same report document defined in §13.2. `GET /healthz` returns
readiness for the platform's probe. Any field omitted from the body falls back to the
environment-variable configuration, so a function can be deployed fully pre-configured and
called with `{"domain": "..."}` alone.

## 5. Pipeline

```
input (domain + exclusions)
      │
      ▼
 [1] ENUMERATE ──► raw subdomains (multi-source, deduplicated)
      │
      ▼
 [2] EXCLUDE ────► in-scope subdomains
      │
      ▼
 [3] RESOLVE ────► live hosts (with A/AAAA/CNAME) + dead hosts
      │
      ▼
 [4] PORTSCAN ───► open ports per live host
      │
      ▼
 [5] HTTP PROBE ─► HTTP(S) services with correct scheme, status, title, tech
      │
      ▼
   report (JSON) ──► stdout | file | webhook
```

### 5.1 Stage selection

Controlled by a single option, `--stages` / `FASTRECON_STAGES`:

| Value | Stages run | Meaning |
|---|---|---|
| `enum` | 1, 2 | Subdomain enumeration only. |
| `resolve` | 1, 2, 3 | Enumeration + live/dead separation. |
| `ports` | 1, 2, 3, 4 | Enumeration + resolution + port scan. |
| `full` | 1–5 | Everything, including HTTP probing. (default) |

Stages form a **strict ladder**: each depends on the one before it, and only the four values
above are accepted. Arbitrary combinations (`enumerate,httpprobe`, skipping the port scan) are
deliberately not supported — probing without a port scan would mean inventing a default port
set, which produces results that look like discovery but are really an assumption. Selecting
`enum` must not perform a single DNS query beyond what the passive sources do themselves.

The report always states which stages ran, so a consumer can tell "no open ports found"
apart from "port scanning did not run".

## 6. Stage 1 — Subdomain enumeration

### 6.1 Engine

Primary engine: **`subfaster` used as a Go library** (`github.com/melvinsh/subfaster`).
It is a fork of ProjectDiscovery's subfinder, so it keeps subfinder's provider-config
format while shipping fast keyless sources (`submd`, `crt`, `thc`, `rapiddns`, `hackertarget`,
`shodanct`, `sitedossier`) and the full keyed source set behind its "all sources" mode.

Only the library's **passive agent** is used, not its CLI runner. The runner reads a provider
config from the user's home directory when none is given, and a container run must not depend
on what happens to be in `$HOME` — nor attempt that read on a read-only filesystem. Driving the
agent directly also removes the runner's resolver initialisation and update check, neither of
which this stage needs.

The engine sits behind an interface:

```go
type Enumerator interface {
    Enumerate(ctx context.Context, domain string) (<-chan Subdomain, error)
    Name() string
}
```

so that `subfinder` (library or binary) or a hand-written source can be substituted without
touching the rest of the pipeline. v1 ships the subfaster-backed implementation; a
`--enumerator` flag selects among registered implementations.

### 6.2 Required sources

These must be supported and enabled by default when credentials are present:

| Source | Engine name | Key | Environment variable |
|---|---|---|---|
| ProjectDiscovery Chaos | `chaos` | required | `CHAOS_API_KEY` |
| SecurityTrails | `securitytrails` | required | `SECURITYTRAILS_API_KEY` |
| c99.nl | `c99` | required | `C99_API_KEY` |
| sub.md | `submd` | optional | `SUBMD_API_KEY` |
| crt.name | `crt` | optional | `CRT_API_KEY` |

The last two work without a credential, which is what makes a run with no keys at all still
return data; a key only improves their results. The three keyed sources report themselves as
`skipped_no_key` rather than being silently dropped from the selection.

This set is the default selection. `--sources` replaces it, `--exclude-sources` subtracts from
it, and `--all-sources` queries everything the engine knows. `fastrecon sources` lists the
available names with their key requirement — an unknown name is rejected at startup rather
than silently ignored, because a misspelled source is a source that never ran.

### 6.3 Behaviour

- Sources run concurrently, each with its own timeout and its own error handling.
- **A failing source is a warning, not a fatal error** — a missing API key, a rate limit, or
  a 5xx degrades the run instead of aborting it. Every source's status
  (`ok` / `skipped_no_key` / `error` / `timeout`) plus the count it contributed is recorded
  in the report, so a silently empty source is visible.
- Results are deduplicated, lowercased, and normalized (trailing dot stripped, IDNA/punycode
  normalized, wildcard entries such as `*.example.com` dropped).
- Out-of-scope results (not equal to the root domain and not a subdomain of it) are dropped.

### 6.4 Rate limits and time ceilings

The intent is **bounded waiting, then abandonment of the source**. Failing fast on the first
429 discards a source that would have answered a couple of seconds later; waiting without a
ceiling lets one throttled source consume the whole run deadline.

What is enforced today, through the engine:

- **A time ceiling per source** — `--source-timeout` (default 30s), which bounds a source's
  whole session, retries and backoff included. When it expires the source is abandoned.
- **A ceiling on the stage** — the enumeration's share of the run deadline, computed by the
  pipeline. Sources run concurrently, so a throttled source never blocks the others; the
  stage ends when every source has finished or when its budget runs out.
- **Results already collected are kept.** A paginated source that returned three pages of
  five contributes those three; it is recorded with `partial: true` rather than discarded.
- **Throttling is distinguished from failure.** A source whose errors carry a 429, a rate-limit
  message or a quota message is recorded as `rate_limited`, not `error` — "refused to answer"
  and "had nothing to say" are different findings.

What is **not** implemented: FastRecon does not schedule the retries itself. The engine owns
its HTTP layer and exposes no retry hook, so honouring `Retry-After` and applying proactive
client-side rate limiting per source would require a hand-written source layer. Until then the
timeout above is the ceiling, and the report says which sources hit it.

## 7. Stage 2 — Exclusions

Exclusions are supplied as a repeatable flag, a file, or an environment variable, and are
applied to the enumeration output before any network activity.

Supported pattern forms:

| Form | Example | Matches |
|---|---|---|
| Exact host | `admin.example.com` | that host only |
| Wildcard suffix | `*.dev.example.com` | any host under `dev.example.com` (and `dev.example.com` itself unless `--exclude-strict-wildcard`) |
| Regex | `re:^(staging\|preprod)[0-9]*\.` | hosts matching the RE2 pattern |

Rules:

- Matching is case-insensitive.
- The root domain itself can be excluded.
- Every exclusion decision is counted; the report contains the number of hosts removed and,
  under `--report-excluded`, the list of removed hosts with the pattern that matched — needed
  to debug an over-broad exclusion.
- An exclusion pattern that matches nothing is reported as a warning (typo detection).

Sources of exclusions, merged together:

- `--exclude <pattern>` (repeatable)
- `--exclude-file <path>` (one pattern per line, `#` comments allowed)
- `FASTRECON_EXCLUDE` (comma- or newline-separated) — the serverless path

## 8. Stage 3 — Live/dead separation

Resolution splits in-scope hosts into **live** and **dead**.

- Engine: **`dnsx` as a Go library** — pure Go, unprivileged, does its own concurrency and
  retries. No `massdns`/`puredns` binary is required in the image.
- Configurable: resolver list (`--resolvers`, default a bundled public set), concurrency,
  extra attempts per query, per-query timeout. Records queried: A, AAAA, CNAME.
- A resolver given without a port gets `:53`, so `1.1.1.1` and `1.1.1.1:53` both work.

A host is **live** if it resolves to at least one address and is not a wildcard artifact.
Everything else is **dead**, with a reason (`nxdomain`, `no_answer`, `timeout`). Dead hosts
stay in the report — a dangling CNAME is a finding, not noise, so the alias target is kept
alongside the verdict.

`nxdomain` and `no_answer` are deliberately distinct: a name that exists but has no address
(MX or TXT records only) is not the same as a name that does not exist.

Hosts the stage never reached before its deadline are reported as `discovered`, not as dead.
Inventing a verdict for a host that was never queried would be worse than admitting the gap.

### 8.1 Wildcard DNS detection

**Mandatory, and per parent domain.** A domain resolving `*.example.com` to a single address
would otherwise flood the live set with junk, and a wildcard on `*.dev.example.com` is just as
capable of it as one on the apex — only the parent it sits on can reveal it.

- Every parent domain appearing in the host list is probed, plus the root, with random names.
- A parent is a wildcard only when a **majority** of its probes answer, so one flaky lookup
  cannot condemn a whole branch. The answers of all probes are unioned, which covers wildcards
  that round-robin between addresses.
- A host is a wildcard artifact when **all** of its addresses belong to a parent's wildcard
  set, or its CNAME target matches the wildcard's. A host answering with the wildcard address
  *and* one of its own is a real host that shares infrastructure.
- Wildcard hosts are marked `wildcard`, excluded from the live set, and **kept in the report**
  with their answers.

Known limitation: a genuine host that resolves to exactly the wildcard's addresses is
indistinguishable from an artifact at the DNS level — `pages.github.io` behind `*.github.io`
is a real example. This is why such hosts are reported rather than dropped: the classification
is recoverable by whatever consumes the report, but deleted data is not.

### 8.2 Not implemented

An external resolver engine (`--resolver-engine=external` shelling out to `puredns`/`massdns`
for their throughput) is not built. dnsx covers the requirement in-process, and shelling out
would mean parsing another tool's output format and shipping its binary — neither of which the
default container image should carry. If throughput ever becomes the constraint, this is where
it gets revisited.

## 9. Stage 4 — Port scanning

- Engine: **`naabu` as a Go library**, in **connect** mode by default (`-s c` equivalent),
  which requires no privileges and works in a serverless job.
- `--scan-mode=syn` is available for privileged local runs; the tool checks for the required
  capability at startup and refuses with an explicit error if absent, instead of degrading
  silently.
- Port selection (`--ports` / `FASTRECON_PORTS`):
  - `top-100` (default), `top-1000`, `web` (a curated HTTP-oriented set),
  - explicit lists and ranges: `80,443,8000-8100`,
  - `--exclude-ports` to subtract.
- Tunables: concurrency, rate limit, connect timeout, retries, per-host and global caps.
- Scanning targets resolved IPs, deduplicated: several subdomains pointing at the same IP are
  scanned once and the results are mapped back onto every host sharing that IP.

### 9.1 CDN and WAF determination

Before a single port is touched, every target address is checked against the known CDN, WAF
and cloud-provider ranges. This is a **determination step, not a filter**: it runs on every
run, and its outcome is recorded whether or not it changes what gets scanned.

naabu exposes the two halves separately, and FastRecon uses both:

| naabu option | Role | Governed by |
|---|---|---|
| `-exclude-cdn` | restrict CDN/WAF addresses to ports 80 and 443 | `--skip-cdn` (default on) |
| `-display-cdn` | report which provider was matched | always on |

- **Why restrict.** A CDN edge answers for thousands of unrelated customers. Its open ports
  describe the provider's infrastructure, not the target's attack surface, so scanning the
  full range burns the budget on results that mean nothing — and looks, from the provider's
  side, like an attack on their edge.
- **Why record it regardless.** "Only 80 and 443 are open" is indistinguishable from a
  genuinely minimal host unless the report states that the scan was deliberately narrowed.
  Every host behind a CDN therefore carries the provider name and a `scan_limited` marker, so
  no consumer mistakes a truncated port list for an exhaustive one.
- `--skip-cdn=false` scans CDN addresses in full. Detection still runs and the provider is
  still recorded; only the restriction is lifted.
- Detection is recorded per provider, each entry naming the addresses it matched, so a host
  with both a CDN address and an origin address shows which is which. The restriction applies
  to the matched addresses only.

## 10. Stage 5 — HTTP probing

- Engine: **`httpx` as a Go library**, run against the *discovered open ports only* — not a
  fixed 80/443 assumption.
- Scheme detection: each `host:port` is tried in the appropriate order and the working scheme
  is recorded, so `https` on 8080 and `http` on 8443 are both reported correctly.
- Collected per service: final URL, scheme, status code, page title, content length,
  redirect chain, response time, TLS subject/SAN/issuer/expiry, detected technologies,
  and the server header.
- Tunables: concurrency, request timeout, follow-redirects toggle and hop limit, custom
  User-Agent and headers, max response size.
- TLS SANs discovered here may reveal additional hostnames; v1 **records** them in the report
  but does not feed them back into the pipeline. (Candidate for v2: a re-enumeration loop.)

## 11. Configuration

### 11.1 Precedence

`CLI flag` > `environment variable` > `config file` > `built-in default`.

Every option is settable through all three mechanisms. The env var name for an option is its
flag name uppercased with `-` → `_`, prefixed `FASTRECON_` (e.g. `--http-timeout` →
`FASTRECON_HTTP_TIMEOUT`). This mechanical mapping is what makes the serverless job
configurable without a config file.

### 11.2 Config file

Optional YAML, selected by `--config` / `FASTRECON_CONFIG`. Never read from an implicit
`$HOME` path unless `--config auto` is passed, so container runs stay deterministic.

### 11.3 Core options (indicative)

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `-d, --domain` | `FASTRECON_DOMAIN` | — | root domain (required) |
| `--exclude`, `--exclude-file` | `FASTRECON_EXCLUDE` | — | exclusion patterns |
| `--stages` | `FASTRECON_STAGES` | `full` | pipeline scope |
| `--ports` | `FASTRECON_PORTS` | `top-100` | port selection |
| `--scan-mode` | `FASTRECON_SCAN_MODE` | `connect` | `connect` \| `syn` |
| `--output`, `-o` | `FASTRECON_OUTPUT` | `-` (stdout) | file sink path |
| `--format` | `FASTRECON_FORMAT` | `json` | `json` \| `jsonl` \| `text` |
| `--webhook-url` | `FASTRECON_WEBHOOK_URL` | — | webhook sink |
| `--timeout` | `FASTRECON_TIMEOUT` | `30m` | global deadline |
| `--concurrency` | `FASTRECON_CONCURRENCY` | tuned per stage | worker counts |
| `--log-level` | `FASTRECON_LOG_LEVEL` | `info` | stderr verbosity |
| `--provider-config` | `FASTRECON_PROVIDER_CONFIG` | — | source credentials file |
| `--sources` | `FASTRECON_SOURCES` | the five above | enumeration sources to query |
| `--exclude-sources` | `FASTRECON_EXCLUDE_SOURCES` | — | sources to subtract from the selection |
| `--all-sources` | `FASTRECON_ALL_SOURCES` | `false` | query every source the engine knows |
| `--source-timeout` | `FASTRECON_SOURCE_TIMEOUT` | `30s` | time ceiling for a single source |
| `--resolvers` | `FASTRECON_RESOLVERS` | bundled set | DNS resolvers to use |
| `--wildcard-probes` | `FASTRECON_WILDCARD_PROBES` | `3` | random names probed per parent domain |
| `--listen` (serve) | `FASTRECON_LISTEN` | `:8080` | HTTP bind address in function mode |
| `--api-token` (serve) | `FASTRECON_API_TOKEN` | — | shared token required by the handler |

## 12. Secrets and API keys

Hard requirement: **the container image contains no credentials**, because CI builds and
publishes it.

Accepted credential sources, in precedence order:

1. **Environment variables** — the primary path for both Docker and Scaleway Jobs.
   Two accepted spellings: the upstream names the enumeration engine already understands
   (`CHAOS_API_KEY`, `SECURITYTRAILS_API_KEY`, `C99_API_KEY`, …) and a namespaced form
   (`FASTRECON_KEY_CHAOS`, …). The namespaced form wins on conflict.
2. **A provider config file** mounted at runtime, path given by `--provider-config`.
   Subfinder/subfaster-compatible YAML. Never copied into the image.
3. **A secret file per key** — `FASTRECON_KEY_CHAOS_FILE=/run/secrets/chaos`, for Docker
   secrets and mounted-volume setups.

Enforcement and hygiene:

- `.dockerignore` excludes `*.yaml` provider configs, `.env*`, and any `secrets/` directory.
- The build must never accept credentials as `--build-arg` (they persist in image history).
- CI runs a secret scanner (gitleaks or equivalent) on the repository and fails the build on
  a hit.
- The tool **redacts credentials in all output and logs**, including error messages that echo
  a request URL (c99 puts the key in the query string — this must be scrubbed).
- Startup emits a credential inventory at `info` level: which sources have a key, which do
  not. Values are never logged, not even truncated.

## 13. Output

### 13.1 Sinks

Sinks are independent and can be combined in a single run:

- **stdout** (default) — the full JSON document. When stdout is a sink, *all* logging goes to
  stderr so stdout stays parseable. This is what makes `fastrecon ... | jq` work locally and
  keeps the job's logs readable in Cockpit.
- **file** — `--output ./results/report.json`; parent directories created as needed. Written
  atomically (temp file + rename) so a consumer never reads a half-written report.
- **webhook** — `--webhook-url`; an HTTP POST of the full report document as raw JSON
  (`Content-Type: application/json`), unchanged from what the other sinks emit. The target is
  an internal API, not a chat destination, so there is no message formatting and no summary
  variant: one shape, defined in §13.2, for every consumer. Options: `--webhook-method`
  (default `POST`), `--webhook-header` (repeatable, for auth — e.g. a bearer token or an
  internal signature header), `--webhook-timeout`, and `--webhook-retries` with exponential
  backoff on 5xx, 429, and transport errors (never on 4xx, which will not become valid on a
  retry). A delivery failure sets a non-zero exit code but does not discard the other sinks'
  output — the report must still reach stdout or the file sink.

Formats: `json` (single document, default), `jsonl` (one host per line, stream-friendly for
large scopes), `text` (human-readable summary).

### 13.2 Report shape (indicative)

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
      "cdn": [{"name": "cloudflare", "type": "waf", "addresses": ["93.184.216.34"], "scan_limited": true}],
      "ports": [
        {"port": 443, "protocol": "tcp", "state": "open",
         "http": {
           "url": "https://api.example.com",
           "scheme": "https",
           "status_code": 200,
           "title": "API",
           "content_length": 1533,
           "tech": ["nginx"],
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

`completed: false` plus `truncated_by_timeout: true` is how a deadline-truncated run is
reported — the report is still emitted and still valid.

A host carries the status of the furthest stage that reached it. In an `enum` scope nothing is
resolved, so every surviving host is `discovered`: the enumeration result is data in its own
right and must appear in the report, not merely be counted in `stats`.

### 13.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | run completed, report emitted |
| 1 | invalid configuration / usage |
| 2 | report emitted, but the run did not finish its scope — the deadline was reached, or a stage failed or is unavailable |
| 3 | run produced a report, but a sink failed (e.g. webhook delivery) |
| 4 | fatal runtime error, no report produced |

Distinct codes matter because a job scheduler's only signal is the exit status.

## 14. Logging and observability

- All logs go to **stderr**, structured JSON by default (`--log-format=text` for humans),
  keeping stdout clean for the report.
- Per-stage progress lines with counts and durations at `info`; per-host detail at `debug`.
- A final summary line with the same counters as `stats`, so the run outcome is visible in a
  log-only environment (Cockpit) even when the report itself went to a webhook.
- No credential, no full request URL containing a key, ever appears in logs.

## 15. Packaging and CI

### 15.1 Container image

- Multi-stage build: Go builder → `gcr.io/distroless/static` (or `scratch`) final stage.
- Static build (`CGO_ENABLED=0`), with CA certificates and `/etc/passwd` from distroless.
- Runs as a non-root user; no capabilities added; no privileged requirement.
- Entrypoint is the binary, so job args map straight onto CLI flags.
- `linux/amd64` only for now — it is the target job and function runtime. The build is set up
  so a second architecture is a matrix entry, not a rewrite.
- Version, commit, and build date injected via `-ldflags`, surfaced by `fastrecon version`
  and in the report's `run.version`.

### 15.2 CI

GitHub Actions, triggered on push, PR, and tag:

1. lint (`golangci-lint`) + `go vet`
2. unit tests with race detector; integration tests behind a build tag (they need network)
3. secret scan (gitleaks) — build fails on any hit
4. build the `linux/amd64` image, push to the registry (GHCR and/or Scaleway Container Registry)
5. tags: `latest` on default branch, semver on git tags, plus the commit SHA
6. no secret is ever passed as a build arg; registry credentials come from CI secrets only

## 16. Project layout (planned)

```
cmd/fastrecon/            CLI entrypoint, flag/env binding
internal/config/          config resolution + validation + precedence
internal/pipeline/        stage orchestration, deadline budgeting
internal/enumerate/       Enumerator interface + subfaster implementation
internal/exclude/         pattern parsing and matching
internal/resolve/         dnsx implementation, wildcard detection
internal/portscan/        naabu implementation, connect/syn modes
internal/probe/           httpx implementation
internal/report/          report model, JSON schema, formatters
internal/sink/            stdout, file, webhook
internal/secrets/         credential resolution + redaction
internal/httpapi/         `serve` handler for the serverless function deployment
deploy/scaleway/          job + function definition examples, CLI/Terraform snippets
Dockerfile
.github/workflows/
```

## 17. Delivery phases

1. **Skeleton** — module, CLI, config precedence, report model, stdout/file sinks, Dockerfile, CI.
2. **Enumeration + exclusions** — stage 1 and 2 end to end, `--stages enum` fully usable.
3. **Resolution** — stage 3 with wildcard detection.
4. **Port scan** — stage 4, connect mode, CDN handling.
5. **HTTP probe** — stage 5, `--stages full`.
6. **Webhook sink, hardening** — retries, redaction, timeout truncation, exit codes.
7. **Scaleway job deployment** — job definition, env-var configuration, documented run.
8. **Serverless function deployment** — `serve` handler, auth, derived deadline, documented
   container-based function deployment.

