# 00 — Overview

FastRecon takes a root domain, enumerates its subdomains from passive sources, drops the
excluded ones, separates live hosts from dead, scans ports and probes them for HTTP
services. The result is one JSON report.

It is deliberately **not** exhaustive: it maps a perimeter quickly and keeps that map
current on a schedule.

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

Each stage consumes the previous one's output, so the scope is a **ladder**: `--stages`
takes one value and runs everything below it ([table](01-usage.md#choosing-a-scope),
[reasoning](05-design.md#why-a-ladder-and-not-a-set)). The report states which stages ran,
so "no open ports" never reads like "the port scan did not run".

## Where it runs

One container image, one static binary, four environments — there is no separate serverless
build. The default entrypoint is a one-shot run; `serve` puts the same pipeline behind an
HTTP handler.

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

Every other decision comes back to these:

- **One static binary**, no external tools at runtime. It already cost one engine choice
  ([why not naabu](05-design.md#why-not-naabu)).
- **Unprivileged**: no root, no `CAP_NET_RAW`, no raw sockets. That is what makes serverless
  possible, and it rules out SYN scanning.
- **Configurable through environment variables alone** — all a job definition offers.
- **No secret in the image**, which CI publishes publicly.
- **Stateless**: no database, no cross-run diffing. Whatever consumes the report owns that.

## Deliberately not built

- Brute-force subdomain enumeration. Enumeration is passive; a known perimeter is verified
  with an [explicit target list](01-usage.md#scanning-a-known-list).
- Diffing, alerting or storage across runs.
- SYN scanning. `--scan-mode=syn` is refused rather than downgraded: a SYN scan the process
  cannot perform finds nothing, which reads like a host with nothing listening.
- Feeding TLS SANs back into enumeration. They are recorded, not re-enumerated.
