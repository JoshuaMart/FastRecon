# 05 — Design notes

The decisions, the constraints that forced them, and the measurements behind the defaults —
including the options that were tried and rejected. Docs 00–04 describe what the tool does;
this one describes why it does it that way.

Nothing here is required reading to use FastRecon.

## Stack

**Go.** Not a preference — it is what makes the rest cheap:

- Every tool in the target pipeline is Go and importable as a library: `subfaster`
  (enumeration), `dnsx` (resolution), `naabu` (port scan), `httpx` (HTTP probe). Using them
  as packages removes the need to ship and exec external binaries, which is the main source
  of pain in serverless — no package manager, read-only or ephemeral filesystem, binary
  size, PATH assumptions.
- Cross-compiles to a fully static binary → distroless image, small pull, fast cold start.
- The native concurrency model fits a fan-out pipeline of thousands of DNS resolutions and
  TCP connects.

Consequence: the deliverable is a Go module exposing both a `cmd/fastrecon` CLI and an
internal pipeline package, so the pipeline can later be driven from an HTTP handler or a
queue consumer without restructuring. Each stage is an interface in `internal/pipeline` with
one implementation — which is what made two engines replaceable once each was actually run.

## Why a ladder and not a set

`--stages` takes one value and each rung runs everything below it. Arbitrary combinations
are deliberately not expressible.

Probing without a port scan would mean inventing a default port set, which produces results
that look like discovery but are an assumption. The same reasoning runs the other way:
selecting `enum` performs no DNS query beyond what the passive sources make themselves,
which is what lets that scope be described as sending nothing to the target.

## Why a target list exists

Enumeration is authoritative on **presence** and never on **absence**. If a source rate
limits or times out, hosts drop out of the report while nothing changed on the target; a
`resolve` over that output would mark them dead. The per-source accounting makes that
situation visible, which lets a consumer refuse to conclude — but it never lets it conclude.

Verification therefore needs an **explicit list**, because that is the only shape in which a
missing answer means something. `--targets-url` is the twin of `--resolvers-url` and exists
for the same reason: a job with no volume to mount from. `--targets-header` carries the
credential for an authenticated endpoint, and the URL goes through the secret redactor
before it reaches any log.

Two consequences worth spelling out:

- **An over-large list is an error, never a truncation**, and so is a malformed entry. Both
  would turn a host that was never queried into a host that did not answer — the exact false
  death the mode exists to prevent. `--resolvers-url` truncates because a short resolver list
  still works; a short target list does not.
- **Wildcard detection derives its parents from the list alone.** A wildcard floods a
  verification pass just as readily as an enumeration.

## Serverless constraints that shape the design

- **No root, no raw sockets.** `masscan` and `naabu`'s SYN mode are unavailable. The default
  port-scan mode is TCP **connect**, which works unprivileged.
- **stdout is logs, not a return value.** A job's stdout goes to the platform log pipeline.
  It is fine for humans and for debugging, and it is the default output because it is the one
  thing that works everywhere — but a job that must hand results to another system uses the
  webhook sink. This is why the sinks are independent and combinable.
- **Ephemeral, possibly read-only filesystem.** Nothing is written outside the configured
  output path and `$TMPDIR`. No implicit writes to `$HOME` — relevant because
  subfinder/subfaster default to `$HOME/.config/…`, so FastRecon passes provider config
  explicitly instead of relying on that default.
- **Bounded run time.** The tool takes a global deadline and must return a partial,
  well-formed report when it expires rather than being killed mid-flight. Each stage gets its
  own budget derived from the global one.
- **No inbound network (job).** A job is push-only; nothing listens. A container is the
  opposite — it exists to be called — which is why the HTTP entrypoint is a separate
  subcommand rather than always-on behaviour.

### No work after the response

On most such platforms the instance is frozen or reclaimed once the handler returns, so
"answer 202, finish in the background, POST later" loses runs intermittently. The handler
runs **synchronously**. Work that does not fit belongs in a job, and that is the whole split
between the two deployments.

The deadline is derived from the request's `timeout`, else `FASTRECON_TIMEOUT`, minus the
`--output-margin` share reserved to serialize the response. No platform remaining-time
variable is read: none was verifiable for the target platform, and inventing a name would
mislabel every run the day it changed.

### What the request may not set

The enumeration engine keeps API keys on **globally shared source instances** and overwrites
them on each configuration, and the per-source counters that become the report's `sources`
block live on those same instances. Two runs in one process would overwrite each other's
keys and report each other's statistics. Verified in the engine's source, not assumed — and
note that repetition is harmless there, since the keys are replaced rather than appended; it
is concurrency that breaks it.

Three consequences:

- **Credentials and sources are settled once, at startup**, before any stage exists. A
  request cannot supply them, so no request can disturb another's.
- **One run at a time per instance.** A second concurrent request is refused with `429` and a
  `Retry-After` rather than queued: a queued request spends its own deadline waiting and then
  reports a timeout that explains nothing. Deploy with a per-instance concurrency of 1 and
  this never fires; it is a guard, not a mode.
- **No caller-supplied webhook URL.** The caller already receives the report in the response;
  letting them name a destination would turn the endpoint into a request-forwarding gadget
  onto its own network, reachable by anyone holding the token.

Rejected: forking the engine so keys live per run. It is a fork of forty-seven source
integrations to solve what freezing plus a mutex solves for nothing — and not maintaining
those integrations is the whole reason the engine is a dependency.

## Stage 1 — Enumeration

**Engine: `subfaster` as a Go library** (`github.com/melvinsh/subfaster`). A fork of
ProjectDiscovery's subfinder, so it keeps subfinder's provider-config format while shipping
fast keyless sources (`submd`, `crt`, `thc`, `rapiddns`, `hackertarget`, `shodanct`,
`sitedossier`) and the full keyed source set behind its "all sources" mode.

Only the library's **passive agent** is used, not its CLI runner. The runner reads a provider
config from the user's home directory when none is given, and a container run must not depend
on what happens to be in `$HOME` — nor attempt that read on a read-only filesystem. Driving
the agent directly also removes the runner's resolver initialisation and update check,
neither of which this stage needs.

The engine sits behind an interface:

```go
type Enumerator interface {
    Enumerate(ctx context.Context, domain string) (<-chan Subdomain, error)
    Name() string
}
```

so `subfinder` or a hand-written source can be substituted without touching the rest of the
pipeline. v1 ships the subfaster-backed implementation and no way to select another: an
option offering a choice of one would be a flag that does nothing.

Source names are normalized to lower case before they reach the engine, whose lookup is
case-sensitive and which calls `os.Exit` on an empty selection.

### Rate limits and time ceilings

The intent is **bounded waiting, then abandonment of the source**. Failing fast on the first
429 discards a source that would have answered a couple of seconds later; waiting without a
ceiling lets one throttled source consume the whole run deadline. Hence `--source-timeout`
plus the stage's share of the run budget, results already collected kept and marked
`partial`, and throttling recorded as `rate_limited` rather than `error` — "refused to
answer" and "had nothing to say" are different findings.

**Not implemented:** FastRecon does not schedule the retries itself. The engine owns its HTTP
layer and exposes no retry hook, so honouring `Retry-After` and applying proactive
client-side rate limiting per source would require a hand-written source layer. Until then
the timeout is the ceiling, and the report says which sources hit it.

## Stage 3 — Resolution

**Engine: `dnsx` as a Go library** — pure Go, unprivileged, does its own concurrency and
retries. No `massdns`/`puredns` binary is required in the image.

### On large published resolver lists

Lists like `trickest/resolvers` (~12,900 entries) exist for brute-force workloads: millions
of queries that need spreading across many resolvers. That is not this stage's workload,
which resolves the passive enumeration output — thousands of names at most. Measured on the
same 30 hosts, from one network:

| Pool | Resolution time |
|---|---|
| bundled default (6) | 0.8 s |
| `resolvers-trusted.txt`, 17 usable after validation | 23 s |
| `resolvers.txt` (12,925), unvalidated | 49 s |

The large pool is slower and less reliable for this workload, not faster. It remains
available because it is the right tool if brute-force enumeration is ever added.

### Why validate, and why three anchors

A published list is validated by whoever publishes it, from wherever their validator runs,
which says nothing about reachability from inside this job's network. Measured against
`resolvers-trusted.txt`: **14 of its 31 entries were unusable** from one network,
independently confirmed with `dig`.

The known-answer probe draws its name from three anchors run by three operators
(`one.one.one.one`, `dns.google`, `dns.quad9.net`), tried in order — the first correct answer
settles it, so the common case still costs one query. The others exist because a single
anchor is one operator's decision, or one network filter, away from failing every resolver in
the pool at once. A resolver is only called a liar when every anchor that answered came back
with addresses nobody publishes.

A pool where **every** resolver fails is far more often a local condition — no egress on port
53, a captive network, a blocked anchor — than a pool that is genuinely all hostile. The run
continues on the unvalidated pool and says so, as a report warning, a `resolvers_unvalidated`
code and an error-level log line. Refusing to run would turn a network problem into no report
at all, which is the one outcome that cannot be inspected afterwards.

The check verifies correctness, not speed. A resolver that answers correctly but slowly stays
in the pool, which is why the table above matters when choosing one.

### Wildcard detection

**Mandatory, and per parent domain.** A domain resolving `*.example.com` to a single address
would otherwise flood the live set with junk, and a wildcard on `*.dev.example.com` is just
as capable of it as one on the apex — only the parent it sits on can reveal it.

- Every parent domain appearing in the host list is probed, plus the root, with random names.
  The root is always probed first. Zones are ranked by how many hosts they cover and capped
  at **500**: each one costs `--wildcard-probes` queries spent before a single host is
  resolved, and a target naming in depth (`<service>.<env>.<region>.example.com`) produces
  thousands of distinct zones whose probing alone would consume the stage budget. What the
  cap leaves out is counted and reported.
- A parent is a wildcard only when a **majority** of its probes answer, so one flaky lookup
  cannot condemn a whole branch. The answers of all probes are unioned, which covers
  wildcards that round-robin between addresses.
- A host is an artifact when **all** of its addresses belong to a parent's wildcard set, or
  its CNAME target matches the wildcard's. A host answering with the wildcard address *and*
  one of its own is a real host that shares infrastructure.

Known limitation: a genuine host resolving to exactly the wildcard's addresses is
indistinguishable from an artifact at the DNS level — `pages.github.io` behind `*.github.io`
is a real example. This is why such hosts are reported rather than dropped: the
classification is recoverable by whatever consumes the report, but deleted data is not.

### Not implemented

An external resolver engine (`--resolver-engine=external` shelling out to `puredns`/`massdns`
for their throughput) is not built. dnsx covers the requirement in-process, and shelling out
would mean parsing another tool's output format and shipping its binary — neither of which
the default container image should carry. If throughput ever becomes the constraint, this is
where it gets revisited.

## Stage 4 — Port scanning

**Engine: a built-in TCP connect scanner.** Connect scanning requires no privileges, which is
what makes it work in a serverless job.

Probes are ordered port-major — every address on one port before moving to the next — so a
single host is never hammered with the whole port list back to back. A refusal is a
definitive answer and is never retried; only timeouts and local file-descriptor exhaustion
are, since those leave the port's state unknown.

Probes are executed by a **fixed pool of workers** reading a stream of targets. One goroutine
per probe would allocate a stack for every address-port pair up front: a full sweep of ten
addresses measured **5.7 GB** peak resident, against **65 MB** for the pool. In a
memory-capped job that is an OOM kill before any report is delivered — worse than the
truncated report the budget design exists to guarantee.

**Only live hosts are scanned.** A dead host has no address to connect to, and a wildcard
artifact is not a host; scanning either spends the budget proving something already known.
Scanning targets resolved addresses, deduplicated: several subdomains pointing at the same
address are scanned once and the result is mapped back onto every host sharing it. Ports
found across a host's several addresses are merged.

Each port records the addresses it was found open on. Without that, one service behind ten
CNAMEs is indistinguishable from ten services: the report would show ten hosts each
apparently running their own copy, when a single address answers for all of them and the port
is not virtual-hosted. Observed on a real target, where ten names shared one address.

### Why not naabu

naabu was the intended engine and its API fits well — `OnResult` callback, stdout disabled,
no `$HOME` writes in library mode. It was implemented, and then removed after the container
was actually run rather than assumed to work:

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

### CDN and WAF determination

Before a single port is touched, every target address is checked against the known CDN, WAF
and cloud-provider ranges. This is a **determination step, not a filter**: it runs on every
run, and its outcome is recorded whether or not it changes what gets scanned.

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
  genuinely minimal host unless the report states the scan was deliberately narrowed.

Detection is recorded per provider, each entry naming the addresses it matched, so a host
with both a CDN address and an origin address shows which is which. The restriction applies
to the matched addresses only.

## Stage 5 — HTTP probing

**Engine: httpx's client**, used at the request level rather than through its CLI runner. The
runner calls `gologger.Fatal` — and therefore `os.Exit` — on several ordinary paths,
including "no input provided", and its enumeration entry point takes no context, so a run
could neither be cancelled nor survive a bad input. Technology detection uses `wappalyzergo`
directly.

Probing targets the **discovered open ports only**. Assuming 80 and 443 would report services
that were never observed and miss the ones on unusual ports, which is the entire reason the
scan runs first.

TLS SANs discovered here may reveal additional hostnames; they are **recorded** but not fed
back into the pipeline. (Candidate for later: a re-enumeration loop.)

### Scheme detection

**HTTPS is tried first on every port**, with plain HTTP as the fallback. There is no
port-number heuristic, because the TLS handshake is the only reliable discriminator.

Trying HTTP first would misclassify TLS ports: a plain request to an HTTPS port commonly
returns a genuine HTTP `400 The plain HTTP request was sent to HTTPS port`, which is
indistinguishable from a working HTTP service. A handshake, by contrast, either succeeds or
fails. The cost is one fast-failing handshake on plain ports, which is worth one rule with no
exceptions to get wrong.

Three consequences the report makes explicit: `url` always matches the probed scheme and port
(overwriting it with the redirect target produced records reading `"scheme": "http"` alongside
`"url": "https://…"`, which is not a description of anything); a certificate is recorded only
for a connection that was itself TLS; and a broken redirect chain still reports its first hop,
marked `redirect_unfollowed` — observed in practice on a Cloudflare DNS address, where port 80
answers `301` toward an HTTPS endpoint that refuses the handshake.

### The certificate public key hash

`cert_spki_hash` is the lowercase hex SHA-256 of the certificate's `SubjectPublicKeyInfo`,
recorded only for a connection that was itself TLS.

It is the **key** and deliberately not the certificate: an SPKI hash survives renewal when
the key is reused, which is what makes it correlate infrastructure over time and find an
origin behind a CDN. `fingerprint_hash.sha256`, which the TLS library does expose, is of the
certificate and changes every renewal. A pivot also has to *discriminate*, which rules out a
handshake fingerprint like JARM — every asset behind one CDN shares it. Measured on one
perimeter: sixteen hosts produced sixteen distinct hashes, while three hosts under one
wildcard certificate produced one.

It costs a second handshake per HTTPS service. The HTTP client hands back the parsed
certificate fields rather than the DER, and nothing in it exposes the peer certificate, so
the value is unreachable from the probe's own response. The extra connection goes through the
rate limiter like any other, and `--probe-spki=false` opts out. `InsecureSkipVerify` is
correct here: an expired or self-signed certificate is a finding, not a reason to refuse to
look.

## Packaging and CI

**Image.** Multi-stage build: Go builder → `gcr.io/distroless/static`. Static build
(`CGO_ENABLED=0`), with CA certificates and `/etc/passwd` from distroless. Runs as a non-root
user, no capabilities added. The entrypoint is the binary, so job args map straight onto CLI
flags. Version, commit and build date are injected via `-ldflags` and surfaced by
`fastrecon version` and the report's `run.version`.

`linux/amd64` and `linux/arm64` are both published. The serverless runtimes only need the
first, but the documented `docker run` is the first thing a reader tries and it fails
outright on Apple Silicon without a matching manifest. The builder cross-compiles from the
native platform, so the second architecture costs a compile rather than emulation.

**CI**, on push, pull request and tag:

1. `go vet` and `golangci-lint`
2. unit tests with the race detector
3. **the binary must still be statically linked** — checked by building it and reading the
   ELF header, for the reason in [Why not naabu](#why-not-naabu)
4. gitleaks over the full history; a hit fails the build
5. multi-arch image build and push to GHCR
6. tags: the branch name, semver on git tags, and `sha-<commit>`. There is no `latest`.

No secret is ever passed as a build argument: they persist in the image history.

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

`make static` is not optional busywork — a dependency that reaches libc through `dlopen`
produces a binary that builds fine, passes every test, and then fails at `exec` inside the
distroless image. CI runs the same check; the incident that prompted it is
[above](#why-not-naabu).
