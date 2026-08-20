![Image](https://github.com/user-attachments/assets/65bada68-8575-4250-a504-d179604e6fb6)

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-green"></a>
  <img src="https://img.shields.io/badge/docker-supported-blue?logo=docker">
  <img src="https://img.shields.io/badge/golang-1.26-blue?logo=go">
</p>

FastRecon is a fast and simple attack-surface discovery tool. It takes a domain
and returns the hosts that answer, the ports they expose and the HTTP services
behind them, as one JSON report.

It is designed to be non-exhaustive and is not intended to be the most complete
solution, but it is ideal for quickly mapping what a domain exposes — and for
keeping that map current on a schedule, from a serverless job, with no machine
to maintain. One static binary, no external tools to install, and nothing that
needs root.

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

Every stage is optional from the top down, so a run costs only what you ask of
it — see [Choosing a scope](#choosing-a-scope).

## Quick start

```sh
# Passive only: nothing is sent to the target.
docker run --rm ghcr.io/joshuamart/fastrecon:main -d example.com --stages enum

# The whole pipeline, as a human-readable summary.
docker run --rm ghcr.io/joshuamart/fastrecon:main \
  -d example.com --stages full --ports web --format text
```

Or build it:

```sh
make build
./bin/fastrecon -d example.com --stages full --format text
```

No API key is required to start: two of the five default sources work without
one, so a first run returns data immediately. Adding keys widens it — see
[Credentials](#credentials).

## Choosing a scope

The pipeline is a ladder. One value selects how far up it goes, and each rung
implies the ones below it.

| `--stages` | Runs | Sends to the target |
|---|---|---|
| `enum` | enumeration + exclusions | nothing |
| `resolve` | + DNS resolution | nothing |
| `ports` | + port scan | TCP connections |
| `full` | + HTTP probe (default) | TCP + HTTP requests |

`enum` and `resolve` are entirely passive from the target's point of view: the
sources and the DNS resolvers are third parties.

Arbitrary combinations are deliberately not expressible. Probing without a port
scan would mean inventing a default port set, which looks like discovery but is
an assumption.

## What a run looks like

```
$ fastrecon -d example.com --stages full --ports 80,443 --format text

run      01M0GHWAB49MM5HBE9057HF08T
domain   example.com
scope    full (enumerate > exclude > resolve > portscan > httpprobe)
duration 2.2s
status   complete

sources
  crt                ok                  75

stats
  enumerated     75
  excluded       0
  in scope       75
  live           16
  dead           59
  wildcard       0
  open ports     32
  http services  32

hosts
  ai.example.com                                  dead      nxdomain
  budget.example.com                              live      80/https(303) 443/https(303)
  cloud.example.com                               live      80/https(302) 443/https(302)
  dashboard.example.com                           live      80/http(308) 443/https(200)
  bitwarden.example.com                           dead      nxdomain
  …
```

`--format json` gives the same run as a document: per-source accounting, the
addresses each port was found on, TLS certificates, detected technologies and
redirect chains. The **[full schema](SPECIFICATIONS.md#132-report-shape)** is in
the specification.

A few things the report is deliberate about, because they change how you read
it:

- **Dead hosts stay in.** A dangling CNAME is a finding, not noise. `nxdomain`
  and `no_answer` are distinct: a name that exists but has no address is not a
  name that does not exist.
- **Every source appears**, successful or not — a source that silently returns
  nothing is exactly what that accounting exists to expose.
- **`scan_limited` marks a narrowed sweep.** "Only 80 and 443 are open" is
  indistinguishable from a genuinely minimal host unless the report says the
  scan was narrowed on purpose.
- **A truncated run is still a valid report**, flagged by `completed` and
  `truncated_by_timeout`. Running out of time is data, not an error.

<details>
<summary>Other output formats</summary>

| `--format` | |
|---|---|
| `json` | one indented document; the default |
| `json-compact` | the same document on one line, for log sinks |
| `jsonl` | one host per line, for large scopes |
| `text` | human-readable summary |

Logs are a place to read a run, not a transport: a collector may split long
lines (Scaleway Cockpit cuts at 16 KiB). Anything a machine consumes should go
to `--webhook-url`.

</details>

## Configuration

<details>
<summary>Options, precedence and exclusions</summary>

Every option is settable three ways, and the names are mechanically related:

| | |
|---|---|
| flag | `--scan-mode connect` |
| environment | `FASTRECON_SCAN_MODE=connect` |
| config file | `scan-mode: connect` |

Precedence is `flag > environment > config file > default`. That mapping is
what lets a serverless job be configured entirely through environment
variables. Run `fastrecon --help` for the full list, which is generated from
the flag definitions and is therefore always current.

**Exclusions** are applied before any network activity touches a host:

```sh
--exclude 'admin.example.com'            # exact
--exclude '*.dev.example.com'            # everything under dev
--exclude 're:^staging[0-9]*\.'          # regexp
--exclude-file ./out-of-scope.txt        # one per line, # comments
```

A pattern that matches nothing is reported as a warning — a typo in an
exclusion means hosts were scanned that should not have been.

In the environment form, lines are the outer separator: a line starting with
`re:` is one pattern kept whole (a regexp's repeat count contains a comma), any
other line is a comma-separated list.

**Ports**: `top-100` (default), `top-1000`, `full`, `web` (a curated
HTTP-oriented set), or an explicit expression like `80,443,8000-8100`, with
`--exclude-ports` to subtract.

**Resolvers**: the bundled default is small and deliberate — Cloudflare, Google
and Quad9's *unfiltered* endpoints. A filtering resolver returns a block-page
address, and one that redirects NXDOMAIN turns every dead host into a live one.
Bring your own with `--resolvers-file` or `--resolvers-url`; they are
health-checked before the run, and the ones that lie or cannot be reached are
dropped.

</details>

## Credentials

<details>
<summary>Sources and where keys come from</summary>

| Source | Engine name | Key |
|---|---|---|
| ProjectDiscovery Chaos | `chaos` | required |
| SecurityTrails | `securitytrails` | required |
| c99.nl | `c99` | required |
| sub.md | `submd` | optional |
| crt.name | `crt` | optional |

The last two work without a credential, which is what makes a first run return
data. The keyed ones report themselves as `skipped_no_key` rather than being
silently dropped. `fastrecon sources` lists everything the engine knows.

Keys are never baked into the image. Provide them at runtime, in this order of
precedence:

1. `FASTRECON_KEY_<SOURCE>` — the namespaced environment variable
2. `<SOURCE>_API_KEY` — the upstream spelling (`CHAOS_API_KEY`, …)
3. a provider config file, pointed at with `--provider-config`
   (subfinder/subfaster format)
4. `FASTRECON_KEY_<SOURCE>_FILE` — a path to a file holding the key, for Docker
   and Kubernetes secret mounts

Credential values never appear in the logs or the report. Error messages are
scrubbed, including request URLs — some sources put the key in the query
string.

</details>

## Serving it over HTTP

<details>
<summary><code>fastrecon serve</code></summary>

The same pipeline behind an authenticated endpoint, for a serverless container:

```sh
fastrecon serve --api-token "$TOKEN"

curl -X POST localhost:8080/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"domain":"example.com","stages":"enum"}'
```

The response is the report document. `GET /healthz` needs no token.

The request says **what** to scan, never how the deployment is wired:
credentials, sources, resolvers and any webhook destination come from the
environment. An unknown field is rejected rather than ignored.

One run at a time per instance — the enumeration engine keeps per-run state on
globally shared instances, so a second concurrent request is refused with `429`
rather than corrupting both. Deploy with a per-instance concurrency of 1 and it
never fires.

</details>

## Deployment

Running it as a Scaleway Serverless Job — with the resource sizing, the
scheduling, and the traps worth knowing — is covered in
**[deploy/scaleway](deploy/scaleway/README.md)**.

## Performance

Example of resources consumption in a Serverless Job with 1000 mvCPU & 1024 MB
RAM, `--stages full --ports web`:

| | 75 subdomains | 617 subdomains |
|---|---|---|
| wall time | 11 s | 384 s |
| memory peak | 223 MiB | 252 MiB |
| CPU peak | 0.59 vCPU | 0.51 vCPU |
| result | 62 HTTP services | 406 HTTP services |

Eight times the hosts for thirteen percent more memory: the cost is dominated
by fixed allocations, not by target size, until the enumeration reaches five or
six figures. The port scan dominates wall time — 289 s of the 384 s above.

![CPU Consumption](https://github.com/user-attachments/assets/40376952-01d0-4261-824f-75d7104dc767)
![RAM Consumption](https://github.com/user-attachments/assets/4005cb1c-d381-434f-b100-1c32618fb2b2)

## Exit codes

<details>
<summary>What each one means, and which ones a scheduler should retry</summary>

| Code | Meaning | Retry? |
|---|---|---|
| 0 | run completed, report emitted | — |
| 1 | invalid configuration or usage | no, it will fail identically |
| 2 | report emitted, scope unfinished | no, the report was delivered |
| 3 | report produced, a destination failed | no, same reason |
| 4 | no report produced, including transient failures | yes |

Only code 4 justifies a retry. A platform that retries on any non-zero exit
will re-run jobs that already delivered their report, so leave retries off
unless duplicates are acceptable.

</details>

## Development

<details>
<summary>Build, test, lint</summary>

```sh
make build   # bin/fastrecon
make test    # go test -race ./...
make lint    # golangci-lint
make cover   # coverage summary
make static  # assert the binary is still statically linked
make docker  # build the image
```

`make static` is not optional busywork — a dependency that reaches libc through
`dlopen` produces a binary that builds fine, passes every test, and then fails
at `exec` inside the distroless image. CI runs the same check; the incident that
prompted it is in [SPECIFICATIONS.md](SPECIFICATIONS.md) §9.

The design, the measurements behind the defaults, and the options that were
tried and rejected are in **[SPECIFICATIONS.md](SPECIFICATIONS.md)**.

</details>
