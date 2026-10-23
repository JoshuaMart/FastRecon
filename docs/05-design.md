# 05 — Design notes

Why FastRecon is built this way: the constraints, the measurements behind the defaults, and
the options tried and rejected. Nothing here is needed to use it.

## Stack

**Go**, because the pipeline's tools are Go libraries: `subfaster` (enumeration), `dnsx`
(resolution), `httpx` (HTTP probe), `cdncheck` (CDN ranges). Importing them instead of
shipping binaries avoids what hurts in serverless — no package manager, a read-only
filesystem, PATH assumptions. Go also cross-compiles to a static binary (distroless image,
fast cold start) and fits a fan-out of thousands of queries and connections.

Each stage is an interface in `internal/pipeline` with one implementation, which is what let
two engines be replaced once they were actually run. `internal/app` builds a run for both the
CLI and the HTTP handler, so the two cannot drift.

## Why a ladder and not a set

Probing without a port scan would mean inventing a port set — results that look like
discovery but are an assumption. Conversely, `enum` makes no DNS query of its own, which is
what lets it claim to send nothing to the target.

## Why a target list exists

Enumeration is authoritative on **presence**, never on **absence**: a source that rate-limits
drops hosts that still exist, and a resolve would mark them dead. Per-source accounting makes
that visible but cannot fix it; only an **explicit list** makes a missing answer meaningful.

- **An over-large or malformed list is an error, never a truncation**: either would turn a
  host never queried into one that did not answer. `--resolvers-url` truncates instead,
  because a short resolver list still works.
- **Wildcard detection derives its parents from the list**, since a wildcard floods a
  verification pass as readily as an enumeration.
- `--targets-url` exists for jobs with no volume to mount. Its URL goes through the redactor
  before any log, and a redirect that would carry `--targets-header` to another host or down
  to `http` is refused.

## Serverless constraints

- **No root, no raw sockets**: no `masscan`, no SYN scan. The port scan uses TCP connect.
- **stdout is logs, not a return value.** It is the default because it works everywhere, but
  a job that hands results on uses the webhook — hence independent, combinable sinks.
- **Ephemeral, possibly read-only filesystem.** Nothing is written outside the output path
  and `$TMPDIR`. subfinder/subfaster default to `$HOME/.config/…`, so the provider config is
  passed explicitly.
- **Bounded run time.** One deadline, counted from startup, with a partial report when it
  expires rather than a killed process.
- **No inbound network for a job**, the opposite for a container — so the HTTP entrypoint is
  a subcommand, not default behaviour.

### No work after the response

Most platforms freeze or reclaim the instance once the handler returns, so "202 now, POST
later" loses runs intermittently. The handler is **synchronous**; work that does not fit
belongs in a job. Its deadline is the request's `timeout`, else `FASTRECON_TIMEOUT`, minus
the output margin. No platform remaining-time variable is read: none could be verified.

### What the request may not set

The enumeration engine keeps API keys and per-source counters on **globally shared source
instances**, so two runs in one process overwrite each other's keys and report each other's
statistics (verified in the engine's source). Hence:

- **Credentials and sources are settled once, at startup**; no request can supply them.
- **One run at a time per instance.** A second request gets `429` with `Retry-After` rather
  than a queue, where it would spend its deadline waiting. With a per-instance concurrency of
  1 this never fires.
- **No caller-supplied webhook**: the caller already gets the report, and a destination of
  their choosing would make the endpoint a request-forwarding gadget onto its own network.
- **Exclusions only add up**: a request's `exclude` extends the deployment's, so it cannot
  lift a scope guard.

What a request *may* set is the target — a `domain` or a `targets` list — and how far to
take it. A list goes through the CLI's loader before the run takes the instance, so a bad
entry is refused whole rather than scanned in part.

Rejected: forking the engine to keep keys per run — forty-seven source integrations to
maintain, for what a mutex solves.

## Stage 1 — Enumeration

**Engine: `subfaster` as a library**, a fork of subfinder that keeps its provider-config
format and adds fast keyless sources (`crt`, `thc`, `scanmalware`, `rapiddns`,
`hackertarget`, `shodanct`, `sitedossier`).

Only its **passive agent** is used. The CLI runner reads a provider config from `$HOME` when
none is given and initialises resolvers and an update check this stage does not need. Source
names are lowercased first: the engine's lookup is case-sensitive, and it calls `os.Exit` on
an empty selection.

The engine sits behind `pipeline.Enumerator`
(`Enumerate(ctx, domain) (Enumeration, error)`), so another can be substituted without
touching the pipeline. There is no option to choose one: a choice of one is a flag that
does nothing.

### Rate limits and time ceilings

Bounded waiting, then abandonment. Failing on the first 429 drops a source that would have
answered seconds later; waiting without a ceiling lets one source eat the run. So
`--source-timeout` plus the stage's share of the deadline, partial results kept and marked,
and throttling reported as `rate_limited` rather than `error`.

**Not implemented:** retries scheduled by FastRecon itself. The engine owns its HTTP layer
and exposes no retry hook, so honouring `Retry-After` per source would need a hand-written
source layer.

## Stage 3 — Resolution

**Engine: `dnsx` as a library** — pure Go, unprivileged, with its own concurrency and
retries. No `massdns`/`puredns` binary in the image.

### On large published resolver lists

Lists like `trickest/resolvers` (~12,900 entries) serve brute-force workloads — millions of
queries. This stage resolves passive enumeration output, thousands of names at most. Same 30
hosts, one network:

| Pool | Resolution time |
|---|---|
| bundled default (6) | 0.8 s |
| `resolvers-trusted.txt`, 17 usable after validation | 23 s |
| `resolvers.txt` (12,925), unvalidated | 49 s |

### Why validate, and why three anchors

A published list is validated from its publisher's network, which says nothing about this
job's: **14 of the 31 entries** of `resolvers-trusted.txt` were unusable from one network,
confirmed with `dig`.

The known-answer probe tries three anchors from three operators (`one.one.one.one`,
`dns.google`, `dns.quad9.net`) in order; the first correct answer settles it. One anchor
would be one operator's decision — or one network filter — away from failing the whole pool.
A resolver is called a liar only when every anchor that answered got addresses nobody
publishes.

When **every** resolver fails, the cause is almost always local (no egress on port 53, a
captive network). The run continues unvalidated and says so — a warning,
`resolvers_unvalidated` and an error log — because refusing would leave no report to
inspect. A check cut short by its caller is not cached.

The check is about correctness, not speed: a slow but honest resolver stays.

### Wildcard detection

**Mandatory, per parent domain**: a wildcard on `*.dev.example.com` floods the live set as
surely as one on the apex.

- Every parent in the host list is probed with random names, the root first. Zones are
  ranked by hosts covered and capped at **500**: a deeply named target
  (`<service>.<env>.<region>.example.com`) produces thousands of zones, each costing
  `--wildcard-probes` queries before any host is resolved. The overflow is reported.
- A parent is a wildcard only when a **majority** of its probes answer, and their answers are
  unioned to catch round-robin wildcards.
- A host is an artifact when **all** its addresses are in a parent's wildcard set, or its
  CNAME matches the wildcard's. One extra address of its own makes it a real host.

Known limitation: a real host resolving to exactly the wildcard's addresses
(`pages.github.io` under `*.github.io`) looks like an artifact. That is why wildcard hosts
are reported, not dropped.

A resolver error (SERVFAIL, REFUSED) leaves the host `discovered`: the failure is the
resolver's, and calling the host dead would be a finding the run did not make.

**Not implemented:** shelling out to `puredns`/`massdns` for throughput. dnsx is enough, and
an external engine means another binary and output format in the image.

## Stage 4 — Port scanning

**Engine: a built-in TCP connect scanner**, which needs no privileges.

- Probes are **port-major** — every address on one port, then the next — so no host takes
  the whole port list back to back.
- **Only a refusal means closed**, and it is not retried. Timeouts are retried as
  `filtered`; local limits (file descriptors, ephemeral ports) are retried with backoff as
  `unknown`; no route from the scanner is `unknown`; a dial the run itself cancelled is not
  counted.
- A **fixed worker pool** reads a stream of targets. A goroutine per probe peaked at
  **5.7 GB** on a full sweep of ten addresses, against **65 MB** for the pool — an OOM kill
  in a capped job.
- **Only live hosts are scanned**, by address, deduplicated: several names on one address are
  scanned once and the result mapped back to each. Each port records the addresses it was
  found on — on one real target, ten names shared a single address.

### Why not naabu

naabu was the intended engine; it was implemented and removed once the container actually
ran. It reaches `sendmmsg` through `purego.Dlopen("libc.so.6")`, unconditionally on Linux,
and `//go:cgo_import_dynamic` makes the binary **dynamically linked even with
`CGO_ENABLED=0`**. `distroless/static` has no dynamic loader, so exec failed with `no such
file or directory`, naming nothing about the cause.

The choice was naabu or the static image. naabu's only extra was SYN mode, which needs
privileges the targets do not grant. CI now asserts the binary is static, since this failure
only shows when the image runs.

### CDN and WAF determination

Before the scan, every address is checked against known CDN, WAF and cloud ranges
(`cdncheck`). This is a **determination, not a filter**: the provider is always recorded,
and only `--skip-cdn` (default on) restricts those addresses to ports 80 and 443.

- **Why restrict**: an edge answers for thousands of customers. Its ports describe the
  provider, not the target, and a full sweep looks like an attack on the edge.
- **Why record regardless**: "only 80 and 443 open" is indistinguishable from a minimal host
  unless the report says the scan was narrowed.

Entries are per provider with the addresses they matched, so a host with a CDN address and
an origin address shows which is which.

## Stage 5 — HTTP probing

**Engine: httpx's client**, at the request level. Its runner calls `os.Exit` on ordinary
paths such as empty input, and takes no context. Technologies come from `wappalyzergo`.

Only the **discovered open ports** are probed: assuming 80 and 443 would report services
never observed and miss unusual ports. TLS SANs are recorded but not fed back into
enumeration.

### Scheme detection

**HTTPS first on every port**, plain HTTP as the fallback, no port-number heuristic. A plain
request to a TLS port often gets a genuine `400 The plain HTTP request was sent to HTTPS
port`, which looks like a working HTTP service; a handshake either succeeds or fails.

The first hop is always requested on its own, and redirects are followed in a second request
only when it answered with one. So:

- `url` always matches the probed scheme and port (overwriting it with the redirect target
  once produced `"scheme": "http"` next to `"url": "https://…"`);
- the certificate is the probed endpoint's, never the redirect target's;
- a port that does not answer costs one attempt per scheme;
- a chain that breaks later still reports its first hop, marked `redirect_unfollowed` — seen
  on a Cloudflare DNS address whose port 80 redirects to an HTTPS endpoint refusing the
  handshake.

### The certificate public key hash

`cert_spki_hash` is the hex SHA-256 of the certificate's `SubjectPublicKeyInfo`. It is the
**key**, not the certificate: it survives a renewal that reuses the key, so it correlates
infrastructure over time and can find an origin behind a CDN. The certificate fingerprint
changes on every renewal, and JARM does not discriminate (every asset behind one CDN shares
it). On one perimeter, sixteen hosts gave sixteen hashes, and three under one wildcard
certificate gave one.

It costs a second handshake per HTTPS service, bounded by the stage deadline, because the
HTTP client exposes parsed fields but not the DER. `--probe-spki=false` skips it.
`InsecureSkipVerify` is deliberate: an expired or self-signed certificate is a finding.

## Packaging and CI

**Image.** Go builder → `gcr.io/distroless/static`, `CGO_ENABLED=0`, non-root, no added
capabilities. The entrypoint is the binary, so job arguments map onto flags. Version, commit
and date are injected with `-ldflags` (`fastrecon version`, `run.version`).

`linux/amd64` and `linux/arm64` are published: the serverless runtimes need only the first,
but `docker run` on Apple Silicon fails without the second. The builder cross-compiles
natively, so it costs a compile, not emulation.

**CI**, on push, pull request and tag:

1. `go vet` and `golangci-lint`
2. tests with the race detector
3. **the binary must be statically linked**, checked on the ELF header ([why](#why-not-naabu))
4. gitleaks over the full history
5. multi-arch build and push to GHCR
6. tags: branch name, semver on git tags, `sha-<commit>` — no `latest`

## Project layout

```
cmd/fastrecon/       CLI entrypoint, subcommand dispatch, exit codes
internal/app/        run assembly, shared by the CLI and the HTTP handler
internal/config/     resolution, precedence, validation
internal/pipeline/   stage ladder, deadline budgeting, partial results
internal/enumerate/  subfaster-backed Enumerator, target lists
internal/exclude/    exclusion pattern parsing and matching
internal/resolve/    dnsx-backed resolver, resolver pool, wildcard detection
internal/portscan/   TCP connect scanner, port selections, CDN determination
internal/probe/      httpx-backed HTTP prober, SPKI hashing
internal/serve/      the `serve` handler
internal/report/     report model and formatters
internal/sink/       stdout, file, webhook
internal/secrets/    credential resolution and redaction
internal/ratelimit/  token bucket, shared by the scan and the probe
internal/stage/      the scope ladder
internal/runid/      run identifiers
internal/logging/    structured logging setup
internal/version/    build metadata
```

## Working on it

```sh
make build   # bin/fastrecon
make test    # go test -race ./...
make lint    # golangci-lint
make cover   # coverage summary
make static  # assert the binary is still statically linked
make docker  # build the image
```

Run `make static` after touching dependencies: a library that reaches libc through `dlopen`
builds, passes every test, and then fails at `exec` in the distroless image.
