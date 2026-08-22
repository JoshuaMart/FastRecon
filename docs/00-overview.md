# 00 — Overview

FastRecon takes a root domain, enumerates its subdomains from passive sources, drops the
excluded ones, separates live hosts from dead, scans ports and probes them for HTTP
services. The result is one JSON report.

It is deliberately **not** exhaustive. It exists to map a perimeter quickly and to keep that
map current on a schedule — not to be the most complete discovery tool available.

## The pipeline

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

Each stage consumes the previous one's output, which is why the scope is a **ladder** rather
than a set: `--stages` takes one value and each rung runs everything below it. See
[Choosing a scope](01-usage.md#choosing-a-scope) for the table, and
[Why a ladder and not a set](05-design.md#why-a-ladder-and-not-a-set) for the reasoning.

The report always states which stages ran, so "no open ports found" stays distinguishable
from "port scanning did not run".

## Where it runs

The same artifact — one container image, one static binary — serves four environments. There
is no separate "serverless build". The binary exposes two entrypoints: the default one-shot
CLI run, and a `serve` subcommand that turns the same pipeline into an HTTP handler.

| | Local CLI | Docker (local) | Serverless Job | Serverless Container |
|---|---|---|---|---|
| Invocation | `fastrecon -d example.com` | `docker run … fastrecon -d …` | job definition: image + args + env | HTTP request to `fastrecon serve` |
| Config source | flags, env, config file | flags, env, mounted config file | env vars + startup args | env vars + per-request JSON body |
| Secrets | env / config file | env / mounted file | job env vars | env vars / Secret Manager |
| stdout JSON | read directly | read directly | captured as logs — readable, not machine-retrievable | logs only; the report goes in the response |
| Result delivery | stdout / file | stdout / mounted volume file | **webhook** (primary), stdout for inspection | **HTTP response** (primary) |
| Privileges | can be root | can add `--cap-add=NET_RAW` | unprivileged, no capabilities | unprivileged, no capabilities |
| Time budget | unbounded | unbounded | the job's configured timeout | the request timeout — the tightest of the four |
| Realistic scope | any | any | any, up to the job timeout | `enum` / `resolve` on bounded scopes |

[Deployment](04-deployment.md) covers the last two in detail.

## Constraints

These are what every other decision keeps coming back to:

- **One static binary**, no runtime dependency on external tools. A target rather than an
  absolute rule, but the default image stays self-contained — it has already cost one engine
  choice.
- **Unprivileged.** No root, no `CAP_NET_RAW`, no raw sockets on the default path. This is
  what makes a serverless deployment possible at all, and it rules out SYN scanning.
- **Configurable entirely through environment variables**, since that is all a job
  definition offers.
- **No secret in the image.** CI builds it and publishes it publicly.
- **Stateless.** Every run is self-contained. No database, no cross-run diffing: whatever
  consumes the report owns that.

## Deliberately not built

- Active brute-force subdomain enumeration. Enumeration is passive; verification of a known
  perimeter is done with an [explicit target list](01-usage.md#scanning-a-known-list).
- Cross-run diffing, alerting or storage. The report is the output; a consumer owns history.
- SYN scanning on the default path. `--scan-mode=syn` is refused rather than silently
  downgraded, because a SYN scan the process cannot perform finds no open ports at all —
  which reads exactly like a host with nothing listening.
- Feeding TLS SANs back into enumeration. They are recorded, not re-enumerated.
