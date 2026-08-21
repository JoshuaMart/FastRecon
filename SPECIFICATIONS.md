# FastRecon — Specifications

> What this is: the design record. It states the decisions, the constraints that forced
> them, and the measurements behind the defaults — including the options that were tried and
> rejected, and the things that are deliberately not built.
>
> [README.md](README.md) is the introduction and the usage guide. This document does not
> repeat it, and the flag reference lives in `fastrecon --help`, which is generated from the
> definitions and cannot drift.

## 1. Overview

FastRecon takes a root domain and an exclusion list, enumerates subdomains from passive
sources, drops the excluded ones, separates live hosts from dead, scans ports and probes
them for HTTP services.

It runs identically in four environments:

- as a local CLI binary,
- inside a Docker container,
- as a serverless job (primary target: Scaleway Serverless Jobs),
- behind an HTTP endpoint (primary target: Scaleway Serverless Containers).

The same artifact — one container image, one binary — serves all four. There is no separate
"serverless build". The binary exposes two entrypoints: the default one-shot CLI run, and a
`serve` subcommand that turns the same pipeline into an HTTP handler for the function
deployment.

## 2. Constraints

These are what the rest of the document keeps coming back to.

- **One static binary**, no runtime dependency on external tools. A target rather than a
  hard rule — shelling out is acceptable where it buys something real — but the default
  image stays self-contained. It has already cost one engine choice (§9).
- **Unprivileged.** No root, no `CAP_NET_RAW`, no raw sockets on the default path. This is
  what makes a serverless deployment possible at all, and it rules out SYN scanning.
- **Configurable entirely through environment variables**, since that is all a job
  definition offers.
- **No secret in the image.** CI builds it and publishes it publicly.
- **Stateless.** Every run is self-contained. No database, no cross-run diffing: whatever
  consumes the report owns that.

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

### 4.2 The HTTP deployment

The same image, started with `serve` instead of a one-shot run: one artifact, one code path,
since the handler builds a run configuration and calls the pipeline the CLI calls.

- **The request timeout is the binding constraint.** It is materially shorter than a job's, so
  a full five-stage run over a large scope will not fit. `enum` and `resolve` are what this
  deployment is for; `ports` and `full` are permitted and the caller owns the risk. The
  requested scope is never silently downgraded — it runs what was asked and returns a
  truncated report if the deadline hits.
- **The deadline is derived.** The request's `timeout`, else `FASTRECON_TIMEOUT`, minus the
  `--output-margin` share reserved to serialize the response, so the caller receives a
  well-formed truncated report instead of a platform-level timeout. No platform
  remaining-time variable is read: none was verifiable for the target platform, and inventing
  a name would mislabel every run the day it changed.
- **No work after the response.** On most such platforms the instance is frozen or reclaimed
  once the handler returns, so "answer 202, finish in the background, POST later" loses runs
  intermittently. The handler runs **synchronously**. Work that does not fit belongs in a
  job, and that is the whole split between the two deployments.
- **Authentication.** A shared token compared in constant time, on top of whatever the
  platform provides. `serve` refuses to start without one: an unauthenticated
  subdomain-enumeration endpoint is free reconnaissance for whoever finds it, charged to your
  API quotas.
- **Concurrency.** See §4.3 — the hardest constraint of this deployment.

#### Contract

`POST /run` with a bearer token; the body names a domain and, optionally, `exclude`,
`stages`, `ports` and `timeout`. Anything omitted falls back to the environment, so a
pre-configured deployment is called with `{"domain": "..."}` alone. Anything **not** in that
list is rejected rather than ignored — see §4.3 for what is excluded and why. The response is
the report document of §13.2. `GET /healthz` needs no token, which is what makes it usable as
a platform probe.

This deployment builds **no sinks**: the report is the response. A `--webhook-url` configured
on the function is validated at startup and then never fires, which from the outside is
indistinguishable from one that fires and is never received — so `serve` logs a warning about
it at startup rather than leaving it to be discovered.

| Status | Meaning |
|---|---|
| `200` | report produced — **including a partial one**, which says so in `completed` and `truncated_by_timeout` |
| `400` | malformed body, or a configuration the run rejected |
| `401` | missing or wrong token |
| `429` | a run is already in progress on this instance; `Retry-After` set |
| `500` | a transient failure of ours: no report produced |

The `400`/`500` split mirrors the exit codes: a preparation failure marked transient is ours,
anything else is the caller's. Not every option can be checked before a stage is built — a
port expression is parsed by the scanner — so some caller mistakes surface once the run
starts and still return `400`, with the offending part named.

### 4.3 What the request may not set, and why

The request says **what to scan**, never how the deployment is wired. Credentials, the source
selection, the resolver pool and the webhook destination come from the function's
environment.

This is not tidiness. The enumeration engine keeps API keys on **globally shared source
instances** and overwrites them on each configuration, and the per-source counters that become
the report's `sources` block live on those same instances. Two runs in one process would
overwrite each other's keys and report each other's statistics. Verified in the engine's
source, not assumed — and note that repetition is harmless there, since the keys are replaced
rather than appended; it is concurrency that breaks it.

Two consequences, and one rejected option:

- **Credentials and sources are settled once, at startup**, before any stage exists. A request
  cannot supply them, so no request can disturb another's.
- **One run at a time per instance.** A second concurrent request is refused with `429` and a
  `Retry-After` rather than queued: a queued request spends its own deadline waiting and then
  reports a timeout that explains nothing. Deploy the function with a per-instance concurrency
  of 1 and this never fires; it is a guard, not a mode.
- **No caller-supplied webhook URL.** The caller already receives the report in the response;
  letting them name a destination would turn the function into a request-forwarding gadget
  onto its own network, reachable by anyone holding the token.

Rejected: forking the engine so keys live per run. It is a fork of forty-seven source
integrations to solve what freezing plus a mutex solves for nothing — and not maintaining
those integrations is the whole reason the engine is a dependency.

## 5. Pipeline

Five stages, drawn in the [README](README.md). Each consumes the previous one's
output, which is why the scope is a ladder rather than a set.

### 5.1 Why a ladder and not a set

`--stages` takes one value — `enum`, `resolve`, `ports`, `full` — and each rung runs
everything below it. The [README](README.md#choosing-a-scope) has the table.

Arbitrary combinations are deliberately not expressible. Probing without a port scan would
mean inventing a default port set, which produces results that look like discovery but are
an assumption. Selecting `enum` performs no DNS query beyond what the passive sources make
themselves, which is what lets that scope be described as sending nothing to the target.

The report always states which stages ran, so "no open ports found" is distinguishable from
"port scanning did not run".

## 6. Stage 1 — Enumeration, or a supplied list

Stage 1 answers "what hosts does this run cover", and it has two implementations.

### 6.0 Why a target list exists

Enumeration is authoritative on **presence** and never on **absence**. If a source rate limits
or times out, hosts drop out of the report while nothing changed on the target; a `resolve`
over that output would mark them dead. The per-source accounting makes that situation visible,
which lets a consumer refuse to conclude — but it never lets it conclude.

Verification therefore needs an **explicit list**, because that is the only shape in which a
missing answer means something. `--targets`, `--targets-file` and `--targets-url` supply one;
`--targets-url` is the twin of `--resolvers-url` and exists for the same reason, a job with no
volume to mount from. `--targets-header` carries the credential for an authenticated endpoint,
and the URL goes through the secret redactor before it reaches any log.

Decisions:

- **A list replaces stage 1, it does not skip it.** The ladder is unchanged and exclusions
  still run on its output — a useful second net when a scope rule changed between a run being
  defined and starting.
- **`-d/--domain` becomes optional and purely informational.** It labels the report so a
  consumer can correlate; nothing else reads it.
- **The root filter does not apply.** A verification list legitimately spans several apexes of
  one perimeter, so a supplied host is in scope by definition. The rest of the normalization
  stays: lowercase, trailing dot, IDNA, wildcard label dropped. A host carrying a port is
  rejected, since ports are a run-level setting.
- **Wildcard detection derives its parents from the list alone.** A wildcard floods a
  verification pass just as readily as an enumeration.
- **The endpoint returns `text/plain`, one host per line, LF.** Blank lines and `#` comments
  are ignored, so a generator may emit them or not. The content type is not checked: a server
  sending `application/octet-stream` for a text file is not a reason to refuse the list. A
  host carrying a scheme, a path or a port is an error, not something to strip.
- **An over-large list is an error, never a truncation**, and so is a malformed entry. Both
  would turn a host that was never queried into a host that did not answer — the exact false
  death the mode exists to prevent. `--resolvers-url` truncates because a short resolver list
  still works; a short target list does not.
- **An empty list refuses to start**, like an empty source selection.
- **`run.input`** is `domain` or `targets`. In targets mode `sources` is empty and
  `stats.enumerated` counts the supplied hosts; neither is self-describing, and a consumer
  reads `input` to know what a missing host means.

### 6.1 Subdomain enumeration

#### Engine

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
touching the rest of the pipeline. v1 ships the subfaster-backed implementation and no way to
select another: an option offering a choice of one would be a flag that does nothing.

#### Required sources

These must be supported and enabled by default when credentials are present:

Five sources must be supported and enabled by default: Chaos, SecurityTrails, c99.nl, sub.md
and crt.name. The [README](README.md#credentials) maps them to engine names and key
requirements.

Two of them work without a credential, which is what makes a run with no keys at all still
return data. The three keyed ones report themselves as `skipped_no_key` rather than being
silently dropped — the distinction between "asked and refused" and "never asked" is the whole
point of the per-source accounting.

This set is the default selection. `--sources` replaces it, `--exclude-sources` subtracts from
it, and `--all-sources` queries everything the engine knows. `fastrecon sources` lists the
available names with their key requirement — an unknown name is rejected at startup rather
than silently ignored, because a misspelled source is a source that never ran.

#### Behaviour

- Source names are normalized to lower case before they reach the engine, whose lookup is
  case-sensitive and which calls `os.Exit` on an empty selection. An unknown name is still
  rejected outright.
- Sources run concurrently, each with its own timeout and its own error handling.
- **A failing source is a warning, not a fatal error** — a missing API key, a rate limit, or
  a 5xx degrades the run instead of aborting it. Every source's status
  (`ok` / `skipped_no_key` / `error` / `timeout`) plus the count it contributed is recorded
  in the report, so a silently empty source is visible.
- Results are deduplicated, lowercased, and normalized (trailing dot stripped, IDNA/punycode
  normalized, wildcard entries such as `*.example.com` dropped).
- Out-of-scope results (not equal to the root domain and not a subdomain of it) are dropped.
- **Each host records the sources that returned it**, sorted. Sorting is not cosmetic: a
  consumer that deduplicates observations by comparing payloads would be defeated by a set
  that came back in a different order every run. The attribution is re-applied after the
  ladder, because the resolve stage rebuilds the host list from scratch.

#### Rate limits and time ceilings

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
- `FASTRECON_EXCLUDE` — the serverless path

The environment form splits on **lines** first. A line beginning with `re:` is one pattern,
kept whole; any other line is a comma-separated list of hosts and wildcards. Regexps have to
be exempt from comma splitting because a repeat count contains one — and cutting
`re:^a{1,3}\.example\.com$` yields two halves that **both still compile**, so the run would
quietly resolve, scan and probe hosts the operator had excluded. Splitting the compact host
form on commas is what keeps it usable in a job's environment variable.

## 8. Stage 3 — Live/dead separation

Resolution splits in-scope hosts into **live** and **dead**.

- Engine: **`dnsx` as a Go library** — pure Go, unprivileged, does its own concurrency and
  retries. No `massdns`/`puredns` binary is required in the image.
- Configurable: concurrency, extra attempts per query, per-query timeout. Records queried:
  A, AAAA, CNAME.
- A resolver given without a port gets `:53`, so `1.1.1.1` and `1.1.1.1:53` both work.

#### Resolver pool

Three sources, merged and deduplicated: `--resolvers` (repeatable), `--resolvers-file` (one
per line, `#` comments), and `--resolvers-url` (fetched at startup over https, for the
serverless deployments which have no volume to mount a file from). Entries must be literal IP
addresses — a resolver given as a hostname would have to be resolved by some other resolver
first, a dependency this stage must not have. Unparseable entries are counted and sampled in
the log rather than silently skipped.

The default is a small bundled set: Cloudflare, Google, and Quad9's **unfiltered** endpoints
(`9.9.9.10`, `149.112.112.10`, not `9.9.9.9`). Non-filtering matters more here than resolver
count: a filtering resolver returns a block-page address for a name it dislikes, and a
resolver that redirects NXDOMAIN turns every dead host into a live one — corrupting exactly
the live/dead split this stage exists to produce.

**On large published resolver lists.** Lists like `trickest/resolvers` (~12,900 entries) exist
for brute-force workloads: millions of queries that need spreading across many resolvers.
That is not this stage's workload, which resolves the passive enumeration output — thousands
of names at most. Measured on the same 30 hosts, from one network:

| Pool | Resolution time |
|---|---|
| bundled default (6) | 0.8s |
| `resolvers-trusted.txt`, 17 usable after validation | 23s |
| `resolvers.txt` (12,925), unvalidated | 49s |

The large pool is slower and less reliable for this workload, not faster. It remains available
because it is the right tool if brute-force enumeration is ever added.

#### Resolver health check

`--validate-resolvers` (default on) probes each resolver twice before the run:

- a **known name with a known answer**, so a resolver that lies is caught rather than merely
  one that is unreachable,
- a **random name that must not exist**, catching NXDOMAIN hijacking.

The known name is drawn from three anchors run by three operators
(`one.one.one.one`, `dns.google`, `dns.quad9.net`). They are tried in order and the first
correct answer settles it, so the common case still costs one query; the others exist because a
single anchor is one operator's decision — or one network filter — away from failing every
resolver in the pool at once. A resolver is only called a liar when every anchor that answered
came back with addresses nobody publishes.

A published list is validated by whoever publishes it, from wherever their validator runs,
which says nothing about reachability from inside this job's network. Measured against
`resolvers-trusted.txt`: **14 of its 31 entries were unusable** from one network, independently
confirmed with `dig`.

The pass is bounded by `--resolver-health-budget` (default 30s). Resolvers it did not reach are
**kept and counted** — dropping them would silently shrink the pool, and claiming they passed
would be a lie. Both the dropped count and the unchecked count reach the report as warnings.

A pool where **every** resolver fails is far more often a local condition — no egress on port
53, a captive network, a blocked anchor — than a pool that is genuinely all hostile. The run
continues on the unvalidated pool and says so, as a report warning and an error-level log line.
Refusing to run would turn a network problem into no report at all, which is the one outcome
that cannot be inspected afterwards.

The check verifies correctness, not speed. A resolver that answers correctly but slowly stays
in the pool, which is why the table above matters when choosing one.

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
  The root is always probed first. Zones are ranked by how many hosts they cover and capped at
  **500**: each one costs `--wildcard-probes` queries spent before a single host is resolved,
  and a target naming in depth (`<service>.<env>.<region>.example.com`) produces thousands of
  distinct zones whose probing alone would consume the stage budget. What the cap leaves out is
  counted and reported as a warning.
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

- Engine: a **built-in TCP connect scanner**. Connect scanning requires no privileges, which
  is what makes it work in a serverless job. Probes are ordered port-major — every address on
  one port before moving to the next — so a single host is never hammered with the whole port
  list back to back, and they are rate-limited by `--scan-rate`.
- A refusal is a definitive answer and is never retried; only timeouts and local file
  descriptor exhaustion are, since those leave the port's state unknown.
- `--scan-mode=syn` is **refused**, not silently downgraded: a SYN scan the process cannot
  perform finds no open ports at all, which reads exactly like a host with nothing listening.

#### Why not naabu

naabu was the intended engine and its API fits well — `OnResult` callback, stdout disabled, no
`$HOME` writes in library mode. It was implemented, and then removed after the container was
actually run rather than assumed to work:

naabu reaches `sendmmsg` through `purego.Dlopen("libc.so.6")` to batch raw sends. On Linux
that path is unconditional, and `//go:cgo_import_dynamic` makes the binary **dynamically
linked even with `CGO_ENABLED=0`**. The `distroless/static` runtime image has no dynamic
loader, so the binary failed at exec with `no such file or directory` — a message that names
nothing about the cause.

The trade was: keep naabu and give up the static image that every deployment here is built
on, or keep the static image and write the connect scanner. The only capability naabu offered
beyond it is SYN mode, which needs privileges the target environments do not grant. CI now
asserts the binary stays statically linked, because this failure is invisible until the image
is executed.
- Port selection (`--ports` / `FASTRECON_PORTS`):
  - `top-100` (default), `top-1000`, `full`, `web` (a curated HTTP-oriented set),
  - explicit lists and ranges: `80,443,8000-8100`,
  - `--exclude-ports` to subtract.
  A malformed expression is rejected at startup with the offending part named, rather than
  inside the engine.
- Tunables: concurrency, rate limit, connect timeout, retries. Both limits are global to the
  run and shared by the two scan passes — one limiter per pass would hand the full configured
  rate to each, so `--scan-rate` would not describe the run.
- Probes are executed by a **fixed pool of `--scan-concurrency` workers** reading a stream of
  targets. One goroutine per probe would allocate a stack for every address-port pair up
  front: a full sweep of ten addresses measured 5.7 GB peak resident, against 65 MB for the
  pool. In a memory-capped job that is an OOM kill before any report is delivered — worse
  than the truncated report the budget design exists to guarantee.
- **Only live hosts are scanned.** A dead host has no address to connect to, and a wildcard
  artifact is not a host — scanning either spends the budget proving something already known.
- **Each host records what its sweep attempted**, in `scan`: `scanned` and the four buckets
  `open`, `refused`, `filtered`, `unknown`, which always sum to it. Without them a report says
  the same thing for opposite findings — a host with nothing listening and a host that was
  never probed both show an empty port list, as do a host that closed everything and one
  behind a firewall that started dropping.
  - `scanned` counts what was **attempted**, so a host narrowed to the web ports by
    `scan_limited` counts those, not the full selection.
  - `unknown` is a probe that failed on a local limit, file descriptors mostly. It says
    nothing about the target, so folding it into `refused` or `filtered` would make
    "everything refused" true over ports that were never tried.
  - `scan` is **absent** when the stage did not run. A zeroed object reads as a sweep that
    tried and found nothing, which is a different claim.
- Scanning targets resolved addresses, deduplicated: several subdomains pointing at the same
  address are scanned once and the result is mapped back onto every host sharing it. Ports
  found across a host's several addresses are merged and deduplicated.
- **Each port records the addresses it was found open on.** Without that, one service behind
  ten CNAMEs is indistinguishable from ten services: the report would show ten hosts each
  apparently running their own copy, when a single address answers for all of them and the
  port is not virtual-hosted. Observed on a real target, where ten names shared one address.

### 9.1 CDN and WAF determination

Before a single port is touched, every target address is checked against the known CDN, WAF
and cloud-provider ranges. This is a **determination step, not a filter**: it runs on every
run, and its outcome is recorded whether or not it changes what gets scanned.

The two halves are independent, and FastRecon does both:

| Half | Role | Governed by |
|---|---|---|
| restriction | scan CDN/WAF addresses for ports 80 and 443 only | `--skip-cdn` (default on) |
| determination | record which provider was matched | always on |

The determination uses `cdncheck`, the same library naabu uses for its own `-exclude-cdn`.
Running it before the scan is what lets the port list be decided per address: the full sweep
for origin addresses, ports 80 and 443 for the edges.

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

- Engine: **httpx's client**, used at the request level rather than through its CLI runner.
  The runner calls `gologger.Fatal` — and therefore `os.Exit` — on several ordinary paths,
  including "no input provided", and its enumeration entry point takes no context, so a run
  could neither be cancelled nor survive a bad input. Technology detection uses
  `wappalyzergo` directly.
- Probing targets the **discovered open ports only**. Assuming 80 and 443 would report
  services that were never observed and miss the ones on unusual ports, which is the entire
  reason the scan runs first.
- Collected per service: probed URL, scheme, status code, page title, content length,
  redirect chain, final URL, response time, server header, detected technologies, and — for
  TLS connections — subject CN, issuer, expiry and SANs.
- **The URL omits the port when it is the scheme's default.** This is not cosmetic: it makes
  a scheme on a non-default port the only kind that keeps its port, so an unusual finding —
  TLS answering on port 80, observed in practice — stands out instead of being lost among
  redundant `:443` suffixes. The connection always uses the explicit port regardless.
- Tunables: concurrency, **rate limit**, request timeout, retries, follow-redirects toggle and
  hop limit, custom User-Agent and headers. The sweep is rate-limited like the port scan: an
  HTTP request costs a target far more than a TCP handshake, so if a ceiling belongs anywhere
  it belongs here. Probes run on a fixed worker pool, for the same reason as the scan.
- **Redirects are not followed by default.** The `Location` target is recorded in `final_url`
  either way, so following them buys the final page's title and status at the cost of a
  request per hop to a host that may be out of scope entirely. `--probe-follow-redirects`
  turns it on.
- TLS SANs discovered here may reveal additional hostnames; they are **recorded** but not fed
  back into the pipeline. (Candidate for later: a re-enumeration loop.)

### 10.2 The certificate public key hash

`cert_spki_hash` is the lowercase hex SHA-256 of the certificate's `SubjectPublicKeyInfo`,
recorded only for a connection that was itself TLS.

It is the key and deliberately not the certificate: an SPKI hash **survives renewal** when the
key is reused, which is what makes it correlate infrastructure over time and find an origin
behind a CDN. `fingerprint_hash.sha256`, which the TLS library does expose, is of the
certificate and changes every renewal. A pivot also has to *discriminate*, which rules out a
handshake fingerprint like JARM — every asset behind one CDN shares it. Measured on one
perimeter: sixteen hosts produced sixteen distinct hashes, while three hosts under one wildcard
certificate produced one.

It costs a second handshake per HTTPS service. The HTTP client hands back the parsed
certificate fields rather than the DER, and nothing in it exposes the peer certificate, so the
value is unreachable from the probe's own response. The extra connection goes through the rate
limiter like any other, and `--probe-spki=false` opts out. `InsecureSkipVerify` is correct
here: an expired or self-signed certificate is a finding, not a reason to refuse to look.

### 10.1 Scheme detection

**HTTPS is tried first on every port**, with plain HTTP as the fallback. There is no
port-number heuristic, because the TLS handshake is the only reliable discriminator.

Trying HTTP first would misclassify TLS ports: a plain request to an HTTPS port commonly
returns a genuine HTTP `400 The plain HTTP request was sent to HTTPS port`, which is
indistinguishable from a working HTTP service. A handshake, by contrast, either succeeds or
fails. The cost is one fast-failing handshake on plain ports, which is worth one rule with no
exceptions to get wrong.

Three consequences the report makes explicit:

- **`url` always matches the probed scheme and port.** Where the redirects landed goes in
  `final_url`. Overwriting `url` with the redirect target produced records reading
  `"scheme": "http"` alongside `"url": "https://…"`, which is not a description of anything.
- **A certificate is recorded only for a connection that was itself TLS.** A plain-HTTP probe
  that follows a redirect to an HTTPS host would otherwise attach that other endpoint's
  certificate to this port.
- **A broken redirect chain still reports its first hop**, marked `redirect_unfollowed`. A
  port answering `301` toward a host whose handshake fails is a finding; failing the whole
  request would report the port as having no service at all. Observed in practice on a
  Cloudflare DNS address: port 80 answers `301` to an HTTPS endpoint that refuses the
  handshake.

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

### 11.3 The option surface

Not reproduced here. `fastrecon --help` is generated from the flag definitions, so it is the
only listing that cannot fall out of step with the binary. The options that carry a design
decision are described in the stage sections above.

## 12. Secrets and API keys

Hard requirement: **the container image contains no credentials**, because CI builds and
publishes it.

Four channels in a fixed precedence, listed in the [README](README.md#credentials). Two
design points behind them: the upstream spellings (`CHAOS_API_KEY`, …) are accepted because
the enumeration engine reads those and nothing else, and the `_FILE` form exists because
Docker and Kubernetes deliver secrets as mounted files rather than variables.

Enforcement and hygiene:

- `.dockerignore` excludes `*.yaml` provider configs, `.env*`, and any `secrets/` directory.
- The build must never accept credentials as `--build-arg` (they persist in image history).
- CI runs a secret scanner (gitleaks or equivalent) on the repository and fails the build on
  a hit.
- The tool **redacts credentials in all output and logs**. Redaction happens where a value
  enters a message — a source error carrying a request URL, for instance, since c99 puts the
  key in the query string. The rendered report is then scrubbed once more before it leaves
  the process, as a last line of defence over whatever was missed.
- Webhook header **values are never logged**; only their names are, since a webhook header is
  exactly where a bearer token goes.
- Startup emits a credential inventory at `info` level: which sources have a key, which do
  not. Values are never logged, not even truncated.

## 13. Output

### 13.1 Sinks

Sinks are independent and can be combined in a single run:

- **stdout** (default) — the full JSON document. When stdout is a sink, *all* logging goes to
  stderr so stdout stays parseable. This is what makes `fastrecon ... | jq` work locally and
  keeps the job's logs readable in Cockpit.
- **file** — `--output ./results/report.json`; parent directories created as needed. Written
  atomically (temp file + rename) so a consumer never reads a half-written report, and with
  mode `0600`: a report names hosts, open ports and certificates, which is reconnaissance on
  whoever it describes if the path is shared.
- **webhook** — `--webhook-url`; an HTTP POST of the full report document as raw JSON
  (`Content-Type: application/json`), unchanged from what the other sinks emit. The target is
  an internal API, not a chat destination, so there is no message formatting and no summary
  variant: one shape, defined in §13.2, for every consumer. Options: `--webhook-method`
  (default `POST`), `--webhook-header` (repeatable, for auth), `--webhook-timeout`, and
  `--webhook-retries`. A delivery failure sets a non-zero exit code but does not discard the
  other sinks' output — the report must still reach stdout or the file sink.

  Retries cover 5xx, 429 and transport errors, with exponential backoff plus jitter so
  several jobs retrying do not synchronise. A `Retry-After` header is honoured over the
  computed wait — the endpoint knows better than the schedule — and the whole wait is capped
  so a long chain cannot outlive its budget. **Every other 4xx is not retried**: the request
  itself is wrong, most often the credentials or the URL, and repeating it only delays the
  error.

  The response body is drained but never logged: a webhook target may echo the payload back,
  and re-logging it would undo the redaction applied upstream.

### 13.2 Report shape

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

`completed: false` plus `truncated_by_timeout: true` is how a deadline-truncated run is
reported — the report is still emitted and still valid.

An operator stopping the job is reported differently: `completed: false` with
`truncated_by_timeout` left **false**. A consumer may reasonably retry a run that ran out of
time, and must not retry one somebody stopped on purpose.

A host carries the status of the furthest stage that reached it. In an `enum` scope nothing is
resolved, so every surviving host is `discovered`: the enumeration result is data in its own
right and must appear in the report, not merely be counted in `stats`.

### 13.2.1 Degraded conditions

`run.degraded` carries machine-readable codes for conditions that narrowed a run, or that
make part of its output unsafe to conclude from.

It runs **parallel to `warnings`**, which stays prose for a human. Matching on prose works
until the wording changes and then stops silently — the failure mode this field exists to
remove. Neither replaces the other.

| Code | Condition |
|---|---|
| `resolvers_unvalidated` | some or all of the pool was used without being validated — the health budget ran out, or every resolver failed the check and the run continued anyway |
| `wildcard_zones_capped` | more zones held hosts than the run could probe for a wildcard |

### 13.3 Exit codes

Five of them, tabulated in the [README](README.md#exit-codes).

They are distinct because a job scheduler's only signal is the exit status, and it keys its
retry on that. A network blip reported as `1` — invalid configuration — is something no
scheduler will ever retry, and a truncated run reported as `0` would be a silent lie about
completeness.

The split runs deeper than the table: a preparation failure is either transient — an
unreachable resolver list, for instance — and therefore ours, or a mistake in the
configuration and therefore the caller's. The HTTP handler makes the same split into `500` and
`400`. A health check that leaves nothing usable is neither: the run continues on the
unvalidated pool and warns, for the reason given in §8.

### 13.4 Delivery is detached from the run

Delivery runs on its own context, derived from `context.WithoutCancel` and bounded by the
share of the budget reserved by `--output-margin`.

A stopped job arrives as a signal that cancels the run's context. The entire point of
catching that signal is that the partial report still reaches its destinations — which
delivering on the cancelled context would prevent. The sinks therefore get a fresh deadline
of their own.

The file sink writes atomically, except to destinations that are not regular files:
`/dev/stdout`, `/dev/null` and named pipes cannot be replaced by a rename, and there is
nothing to make atomic. Those are written through directly.

Four formats, listed in the [README](README.md). Only one of them is a decision worth
recording: **`json-compact`**, the whole document on one line.

A job's report reaches its reader as log lines, and an indented document becomes hundreds of
them — a measured run of 75 hosts produced 1889 — which a collector may reorder or drop.
`jsonl` fixes the line count but emits only hosts, dropping the run metadata, the per-source
accounting and the warnings. One line keeps everything.

It is not a complete answer either: **Scaleway Cockpit splits log lines at 16384 bytes**, so
a 296 KB report from a 617-host run still arrived in 19 pieces. They concatenate back
cleanly, but the conclusion stands — logs are where a run is *read*, not a transport.
Anything a machine consumes goes to the webhook.

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
- `linux/amd64` and `linux/arm64`. The serverless runtimes only need the first, but the
  documented `docker run` is the first thing a reader tries and it fails outright on Apple
  Silicon without a matching manifest. The builder cross-compiles from the native platform,
  so the second architecture costs a compile rather than emulation.
- Version, commit, and build date injected via `-ldflags`, surfaced by `fastrecon version`
  and in the report's `run.version`.

### 15.2 CI

GitHub Actions, on push, pull request and tag:

1. `go vet` and `golangci-lint`
2. unit tests with the race detector
3. **the binary must still be statically linked** — checked by building it and reading the
   ELF header. A dependency that reaches libc through `dlopen` produces a binary that
   compiles, passes every test, and then fails at `exec` in the distroless image with a
   message that names nothing. This has happened once already; see §9.
4. secret scan (gitleaks) over the full history — a hit fails the build. Known-fake test
   fixtures are exempted one literal at a time in `.gitleaks.toml`, never by path: a test
   file can hold a real credential as easily as any other.
5. multi-arch image build and push to GHCR
6. tags: the branch name, semver on git tags, and `sha-<commit>`. **There is no `latest`.**
   Pin a `sha-` tag for anything scheduled.

No secret is ever passed as a build argument: they persist in the image history.

## 16. Project layout

```
cmd/fastrecon/       CLI entrypoint, subcommand dispatch, exit codes
internal/app/        run assembly, shared by the CLI and the HTTP handler
internal/config/     resolution, precedence, validation
internal/pipeline/   stage ladder, deadline budgeting, partial results
internal/enumerate/  subfaster-backed Enumerator
internal/exclude/    exclusion pattern parsing and matching
internal/resolve/    dnsx-backed resolver, resolver pool, wildcard detection
internal/portscan/   TCP connect scanner, port selections, CDN determination
internal/probe/      httpx-backed HTTP prober
internal/serve/      the `serve` handler
internal/report/     report model and formatters
internal/sink/       stdout, file, webhook
internal/secrets/    credential resolution and redaction
internal/ratelimit/  token bucket, shared by the scan and the probe
internal/stage/      the scope ladder
deploy/scaleway/     job and container definitions
```

Each stage is an interface in `internal/pipeline` with one implementation. That is what
makes the engines replaceable — and two already were, once each was actually run.
