# 02 — Configuration

## Precedence

Every option is settable three ways, with mechanically related names:

| | |
|---|---|
| flag | `--scan-mode connect` |
| environment | `FASTRECON_SCAN_MODE=connect` |
| config file | `scan-mode: connect` |

`flag` > `environment` > `config file` > `built-in default`. The variable name is the flag
uppercased, `-` → `_`, prefixed `FASTRECON_` — which is what lets a serverless job be
configured through environment variables alone.

The **config file** is optional YAML, selected with `--config` / `FASTRECON_CONFIG`. Nothing
is read from `$HOME` unless `--config auto` is passed, so container runs stay deterministic.

`fastrecon --help` lists every option. This page covers the ones that carry a decision.

## Time budget

`--timeout` is the deadline for the whole run, counted from startup: fetching a target or
resolver list and the resolver health check come out of it too. Each stage gets a share of
what is left, and `--output-margin` (default 10%) is kept back to build and deliver the
report, so a run that overruns produces a truncated but valid document instead of being
killed.

Under a platform timeout, `FASTRECON_TIMEOUT` must be the **shorter** of the two — see
[Timeouts have to nest](04-deployment.md#timeouts-have-to-nest).

## Exclusions

Applied to the enumeration output, before any network activity touches a host.

| Form | Example | Matches |
|---|---|---|
| Exact host | `admin.example.com` | that host only |
| Wildcard suffix | `*.dev.example.com` | any host under `dev.example.com`, and `dev.example.com` itself unless `--exclude-strict-wildcard` |
| Regex | `re:^(staging\|preprod)[0-9]*\.` | hosts matching the RE2 pattern |

- Matching is case-insensitive, and the root domain itself can be excluded.
- The report counts removed hosts; `--report-excluded` also lists each one with the pattern
  that matched, to debug an over-broad exclusion.
- A pattern that matches nothing raises a warning.

Patterns are merged from `--exclude` (repeatable), `--exclude-file` (one per line, `#`
comments) and `FASTRECON_EXCLUDE`.

`FASTRECON_EXCLUDE` splits on **lines** first. A line starting with `re:` is one pattern,
kept whole; any other line is a comma-separated list. Regexps are exempt from comma
splitting because `re:^a{1,3}\.example\.com$` cut at its comma gives two halves that both
still compile — and the run would scan hosts the operator had excluded.

## Ports

`--ports` takes `top-100` (default), `top-1000`, `full`, `web` (a curated HTTP-oriented
set), or an expression like `80,443,8000-8100`. `--exclude-ports` subtracts from it. A
malformed expression is rejected at startup, naming the offending part.

`--scan-concurrency` and `--scan-rate` are global to the run, shared by both scan passes.

`--skip-cdn` (default on) scans CDN and WAF addresses on ports 80 and 443 only. Detection
runs and the provider is recorded either way
([CDN and WAF determination](05-design.md#cdn-and-waf-determination)).

`--scan-mode=syn` is **refused**, not downgraded, when the process lacks the privileges.

## Resolvers

Three sources, merged and deduplicated:

| | |
|---|---|
| `--resolvers` | repeatable, literal IP addresses |
| `--resolvers-file` | one per line, `#` comments |
| `--resolvers-url` | fetched at startup over `http(s)`, for deployments with no volume |

Entries must be IP addresses (a hostname would need another resolver first); a missing port
means `:53`. Unparseable entries are counted and sampled in the log. Over plain `http`,
`--resolvers-url` logs a warning: the list decides where every query goes.

**The default pool is small on purpose**: Cloudflare, Google and Quad9's *unfiltered*
endpoints (`9.9.9.10`, `149.112.112.10`, not `9.9.9.9`). A filtering resolver answers with a
block page, and one that redirects NXDOMAIN makes every dead host look live — exactly the
split this stage produces. Large published lists are slower here
([measurements](05-design.md#on-large-published-resolver-lists)).

**Health check.** `--validate-resolvers` (default on) asks each resolver a name with a known
answer, to catch liars, and a name that cannot exist, to catch NXDOMAIN hijacking. The pass
is bounded by `--resolver-health-budget` (default 30s). Resolvers it did not reach are
**kept and counted**; the dropped and unchecked counts reach the report as warnings, and a
pool used unvalidated is flagged
[`resolvers_unvalidated`](03-output.md#degraded-conditions).

**Wildcard probing** is mandatory and per parent domain. `--wildcard-probes` sets how many
random names each zone gets. Zones are capped at 500; what the cap leaves out is reported as
`wildcard_zones_capped`.

Records queried: A, AAAA and CNAME.

## HTTP probe

- **Redirects are not followed by default**; the `Location` target is recorded in `final_url`
  either way. `--probe-follow-redirects` adds the final page's status and title, at the cost
  of a second request per redirecting service, possibly to a host out of scope.
- `--probe-spki=false` skips the second handshake behind
  [`cert_spki_hash`](05-design.md#the-certificate-public-key-hash).
- `--probe-rate` limits the sweep like `--scan-rate` limits the scan: an HTTP request costs a
  target far more than a handshake.

## Sources

Four sources are enabled by default:

| Source | Engine name | Key |
|---|---|---|
| ProjectDiscovery Chaos | `chaos` | required |
| SecurityTrails | `securitytrails` | required |
| c99.nl | `c99` | required |
| crt.name | `crt` | optional |

`--sources` replaces the selection, `--exclude-sources` subtracts from it, `--all-sources`
queries everything the engine knows (`fastrecon sources` lists them). An unknown name is
rejected at startup: a misspelled source is a source that never ran.

A failing source is a **warning**, not a fatal error. Each one is reported with its status —
`ok`, `skipped_no_key`, `error`, `timeout` or `rate_limited` — and its count; one that
returned part of its pages is marked `partial`. A keyed source without a key reports
`skipped_no_key` instead of disappearing.

`--source-timeout` (default 30s) bounds a source's whole session, retries included; then the
source is abandoned. Sources run concurrently.

## Credentials

Keys are never baked into the image. Precedence, highest first:

1. `FASTRECON_KEY_<SOURCE>`
2. `<SOURCE>_API_KEY` — the upstream spelling (`CHAOS_API_KEY`), which is what the engine reads
3. a provider config file, `--provider-config` (subfinder/subfaster format)
4. `FASTRECON_KEY_<SOURCE>_FILE` — a path to a file holding the key, for Docker and
   Kubernetes secret mounts

At startup an `info` log line lists which sources have a key; values are never logged.

**Redaction.** Key values are scrubbed where they enter a message — c99, for instance, puts
the key in the URL — and the rendered report is scrubbed once more before leaving the
process. Webhook header values are never logged, only their names.

**Repository hygiene.** `.dockerignore` excludes `*.yaml` provider configs, `.env*` and
`secrets/`. Credentials are never accepted as `--build-arg`, which persists in the image
history. CI runs gitleaks over the full history; known fake fixtures are exempted one
literal at a time in `.gitleaks.toml`, never by path.
