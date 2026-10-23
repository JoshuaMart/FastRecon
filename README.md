![FastRecon](https://github.com/user-attachments/assets/65bada68-8575-4250-a504-d179604e6fb6)

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-green"></a>
  <img src="https://img.shields.io/badge/docker-supported-blue?logo=docker">
  <img src="https://img.shields.io/badge/golang-1.26-blue?logo=go">
</p>

**FastRecon maps what a domain exposes.** Give it a root domain; it returns the hosts that
answer, the ports they expose and the HTTP services behind them, as one JSON report.

One static binary, no external tools, no root, no state: it runs as a scheduled serverless
job with no machine to maintain. It is deliberately not exhaustive — it maps a perimeter
quickly and keeps that map current.

## Quick start

```sh
# Passive: nothing is sent to the target.
docker run --rm ghcr.io/joshuamart/fastrecon:main -d example.com --stages enum

# The whole pipeline, as a human-readable summary.
docker run --rm ghcr.io/joshuamart/fastrecon:main \
  -d example.com --stages full --ports web --format text
```

No API key is needed to start: `crt`, one of the four default sources, works without one.
From source: `make build`, then `./bin/fastrecon -d example.com --format text`.

## The pipeline

```
 [1] ENUMERATE ──► raw subdomains (multi-source, deduplicated)
 [2] EXCLUDE ────► in-scope subdomains
 [3] RESOLVE ────► live hosts (A/AAAA/CNAME) + dead hosts
 [4] PORTSCAN ───► open ports per live host
 [5] HTTP PROBE ─► services with scheme, status, title, tech, TLS
```

`--stages` picks how far a run goes; each rung includes the ones below it.

| `--stages` | Runs | Sends to the target |
|---|---|---|
| `enum` | enumeration + exclusions | nothing |
| `resolve` | + DNS resolution | nothing |
| `ports` | + port scan | TCP connections |
| `full` | + HTTP probe (default) | TCP + HTTP requests |

## A run

```
$ fastrecon -d example.com --stages full --ports 80,443 --format text

run      01M0GHWAB49MM5HBE9057HF08T
domain   example.com
scope    full (enumerate > exclude > resolve > portscan > httpprobe)
duration 2.2s
status   complete

stats
  enumerated 75    live 16    dead 59    open ports 32    http services 32

hosts
  budget.example.com          live      80/https(303) 443/https(303)
  dashboard.example.com       live      80/http(308)  443/https(200)
  ai.example.com              dead      nxdomain
  …
```

`--format json` gives the same run as a document, with per-source accounting, TLS
certificates, technologies and redirect chains. Dead hosts, narrowed scans and truncated
runs are reported, never dropped — see [Reading a report](docs/03-output.md#reading-a-report).

## Performance

Measured in a Scaleway Serverless Job at 1000 mvCPU / 1024 MB, `--stages full --ports web`:

| | 75 subdomains | 617 subdomains |
|---|---|---|
| wall time | 11 s | 384 s |
| memory peak | 223 MiB | 252 MiB |
| CPU peak | 0.59 vCPU | 0.51 vCPU |
| result | 62 HTTP services | 406 HTTP services |

![CPU consumption](https://github.com/user-attachments/assets/40376952-01d0-4261-824f-75d7104dc767)
![RAM consumption](https://github.com/user-attachments/assets/4005cb1c-d381-434f-b100-1c32618fb2b2)

Eight times the hosts for 13% more memory: fixed allocations dominate, not target size. The
port scan takes most of the wall time (289 s of 384 s). [Sizing](docs/04-deployment.md#sizing)
has the formula.

## Documentation

| | |
|---|---|
| [Overview](docs/00-overview.md) | what it is, the pipeline, where it runs |
| [Usage](docs/01-usage.md) | install, scopes, target lists, everyday commands |
| [Configuration](docs/02-configuration.md) | flags, environment, exclusions, ports, resolvers, API keys |
| [Output](docs/03-output.md) | formats, report schema, sinks, exit codes |
| [Deployment](docs/04-deployment.md) | `fastrecon serve`, Scaleway jobs and containers, sizing |
| [Design notes](docs/05-design.md) | the decisions behind it, and how to work on it |

## License

MIT — see [LICENSE](LICENSE).
