# 02 — Configuration

## Precedence

Every option is settable three ways, and the names are mechanically related:

| | |
|---|---|
| flag | `--scan-mode connect` |
| environment | `FASTRECON_SCAN_MODE=connect` |
| config file | `scan-mode: connect` |

`flag` > `environment` > `config file` > `built-in default`.

The environment name for an option is its flag name uppercased with `-` → `_`, prefixed
`FASTRECON_` (`--http-timeout` → `FASTRECON_HTTP_TIMEOUT`). That mechanical mapping is what
lets a serverless job be configured entirely through environment variables.

**Config file**: optional YAML, selected with `--config` / `FASTRECON_CONFIG`. It is never
read from an implicit `$HOME` path unless `--config auto` is passed, so container runs stay
deterministic.

**The full option surface** is `fastrecon --help`, generated from the flag definitions. The
options that carry a design decision are the ones described below.

## Time budget

`--timeout` sets a global deadline for the whole run. Each stage gets its own budget derived
from it, and `--output-margin` reserves a share for building and delivering the report — so
a run that overruns still produces a truncated but well-formed document instead of being
killed mid-flight.

When a deployment imposes its own timeout, `FASTRECON_TIMEOUT` must be **shorter** than it.
See [Timeouts have to nest](04-deployment.md#timeouts-have-to-nest).

## Exclusions

Applied to the enumeration output before any network activity touches a host.

| Form | Example | Matches |
|---|---|---|
| Exact host | `admin.example.com` | that host only |
| Wildcard suffix | `*.dev.example.com` | any host under `dev.example.com` (and `dev.example.com` itself unless `--exclude-strict-wildcard`) |
| Regex | `re:^(staging\|preprod)[0-9]*\.` | hosts matching the RE2 pattern |

Rules:

- Matching is case-insensitive.
- The root domain itself can be excluded.
- Every exclusion decision is counted. The report carries the number of hosts removed and,
  under `--report-excluded`, the removed hosts with the pattern that matched — which is what
  it takes to debug an over-broad exclusion.
- A pattern that matches nothing is reported as a warning (typo detection).

Sources, merged together: `--exclude <pattern>` (repeatable), `--exclude-file <path>` (one
per line, `#` comments), and `FASTRECON_EXCLUDE`.

The environment form splits on **lines** first. A line beginning with `re:` is one pattern,
kept whole; any other line is a comma-separated list of hosts and wildcards. Regexps have to
be exempt from comma splitting because a repeat count contains one — and cutting
`re:^a{1,3}\.example\.com$` yields two halves that **both still compile**, so the run would
quietly resolve, scan and probe hosts the operator had excluded.

## Ports

`--ports` accepts `top-100` (default), `top-1000`, `full`, `web` (a curated HTTP-oriented
set), or an explicit expression like `80,443,8000-8100`. `--exclude-ports` subtracts from
the selection. A malformed expression is rejected at startup with the offending part named,
rather than inside the engine.

Tunables: `--scan-concurrency`, `--scan-rate`, connect timeout and retries. Both limits are
global to the run and shared by the two scan passes — one limiter per pass would hand the
full configured rate to each, so `--scan-rate` would no longer describe the run.

`--skip-cdn` (default on) restricts CDN and WAF addresses to ports 80 and 443. Detection
runs either way and the provider is always recorded; only the restriction is lifted by
`--skip-cdn=false`. See [CDN and WAF determination](05-design.md#cdn-and-waf-determination).

`--scan-mode=syn` is **refused**, not silently downgraded, when the process lacks the
privileges for it.

## Resolvers

Three sources, merged and deduplicated:

| | |
|---|---|
| `--resolvers` | repeatable, literal IP addresses |
| `--resolvers-file` | one per line, `#` comments |
| `--resolvers-url` | fetched at startup over HTTPS, for deployments with no volume to mount |

A resolver given without a port gets `:53`. Entries must be literal IP addresses — a
resolver given as a hostname would have to be resolved by some other resolver first, a
dependency this stage must not have. Unparseable entries are counted and sampled in the log
rather than silently skipped.

**The default pool is small and deliberate**: Cloudflare, Google and Quad9's *unfiltered*
endpoints (`9.9.9.10`, `149.112.112.10` — not `9.9.9.9`). Non-filtering matters more than
resolver count here: a filtering resolver returns a block-page address for a name it
dislikes, and a resolver that redirects NXDOMAIN turns every dead host into a live one,
corrupting exactly the live/dead split the stage exists to produce. Large published lists
are slower and less reliable for this workload — the measurements are in
[Design notes](05-design.md#on-large-published-resolver-lists).

**Health check.** `--validate-resolvers` (default on) probes each resolver twice before the
run: a known name with a known answer, catching a resolver that lies rather than merely one
that is unreachable; and a random name that must not exist, catching NXDOMAIN hijacking.

The pass is bounded by `--resolver-health-budget` (default 30s). Resolvers it did not reach
are **kept and counted** — dropping them would silently shrink the pool, claiming they
passed would be a lie. Both the dropped count and the unchecked count reach the report as
warnings, and a pool used without validation is flagged `resolvers_unvalidated` in
[`run.degraded`](03-output.md#degraded-conditions).

Other tunables: resolution concurrency, extra attempts per query, per-query timeout. Records
queried are A, AAAA and CNAME.

**Wildcard probing** is mandatory and runs per parent domain; `--wildcard-probes` sets how
many random names each zone is probed with. Zones are capped at 500 and what the cap leaves
out is reported as `wildcard_zones_capped`.

## HTTP probe

Tunables: concurrency, rate limit, request timeout, retries, redirect toggle and hop limit,
custom User-Agent and headers.

- **Redirects are not followed by default.** The `Location` target is recorded in
  `final_url` either way, so following them buys the final page's title and status at the
  cost of a request per hop to a host that may be out of scope entirely.
  `--probe-follow-redirects` turns it on.
- `--probe-spki=false` opts out of the second handshake used to compute
  [`cert_spki_hash`](05-design.md#the-certificate-public-key-hash).
- The sweep is rate-limited like the port scan: an HTTP request costs a target far more than
  a TCP handshake, so if a ceiling belongs anywhere it belongs here.

## Sources

Five sources are supported and enabled by default:

| Source | Engine name | Key |
|---|---|---|
| ProjectDiscovery Chaos | `chaos` | required |
| SecurityTrails | `securitytrails` | required |
| c99.nl | `c99` | required |
| sub.md | `submd` | optional |
| crt.name | `crt` | optional |

The last two work without a credential, which is what makes a first run return data. The
keyed ones report themselves as `skipped_no_key` rather than being silently dropped — the
distinction between "asked and refused" and "never asked" is the whole point of the
per-source accounting.

`--sources` replaces the default selection, `--exclude-sources` subtracts from it, and
`--all-sources` queries everything the engine knows. `fastrecon sources` lists the available
names. An unknown name is rejected at startup rather than ignored, because a misspelled
source is a source that never ran.

A failing source is a **warning, not a fatal error**. Every source's status
(`ok` / `skipped_no_key` / `error` / `timeout` / `rate_limited`) and the count it
contributed are recorded, and a source that returned part of its pages is marked
`partial: true` rather than discarded.

`--source-timeout` (default 30s) bounds a source's whole session, retries and backoff
included; when it expires the source is abandoned. The enumeration stage additionally has
its share of the run deadline. Sources run concurrently, so a throttled one never blocks the
others.

## Credentials

Keys are never baked into the image. Provide them at runtime, in this order of precedence:

1. `FASTRECON_KEY_<SOURCE>` — the namespaced environment variable
2. `<SOURCE>_API_KEY` — the upstream spelling (`CHAOS_API_KEY`, …)
3. a provider config file, pointed at with `--provider-config` (subfinder/subfaster format)
4. `FASTRECON_KEY_<SOURCE>_FILE` — a path to a file holding the key, for Docker and
   Kubernetes secret mounts

The upstream spellings are accepted because the enumeration engine reads those and nothing
else. The `_FILE` form exists because Docker and Kubernetes deliver secrets as mounted files
rather than variables.

**Redaction.** Credential values never appear in logs or in the report. Redaction happens
where a value enters a message — a source error carrying a request URL, for instance, since
c99 puts the key in the query string — and the rendered report is scrubbed once more before
it leaves the process. Webhook header *values* are never logged, only their names: a webhook
header is exactly where a bearer token goes.

Startup emits a credential inventory at `info` level — which sources have a key, which do
not. Values are never logged, not even truncated.

**Repository hygiene.** `.dockerignore` excludes `*.yaml` provider configs, `.env*` and any
`secrets/` directory. Credentials are never accepted as `--build-arg`, since those persist
in image history. CI runs gitleaks over the full history and fails the build on a hit; known
fake fixtures are exempted one literal at a time in `.gitleaks.toml`, never by path.
