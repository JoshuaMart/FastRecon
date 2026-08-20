# FastRecon

Attack-surface discovery for a domain: passive subdomain enumeration, exclusion
filtering, live/dead separation, port scanning, and HTTP probing — as a single
static binary that runs the same way locally, in Docker, as a serverless job,
and — through `fastrecon serve` — behind an HTTP endpoint.

The design is specified in **[SPECIFICATIONS.md](SPECIFICATIONS.md)**. Read that
first; this file is only the quick start.

## What it does

- passive subdomain enumeration from multiple sources, with per-source
  accounting in the report,
- exclusion patterns — exact, wildcard and regex — applied before any network
  activity touches a host,
- DNS resolution splitting live from dead hosts, with per-parent wildcard
  detection so a `*.example.com` record cannot flood the live set,
- resolver pools from a file or an https URL, health-checked before the run,
- unprivileged TCP connect port scanning, rate-limited, with CDN and WAF
  determination so a narrowed port list is never mistaken for an exhaustive
  one,
- HTTP probing of the discovered ports, HTTPS-first so the recorded scheme is
  the one that actually worked, with titles, technologies and certificates,
- delivery to stdout, a file, and a webhook, with retries that distinguish
  "not now" from "not like this",
- `fastrecon serve`, the same pipeline behind an authenticated HTTP endpoint,
- pipeline orchestration: the stage ladder, deadline budgeting, truncation
  handling, and exit codes.

Deploying it on Scaleway is covered in
[deploy/scaleway](deploy/scaleway/README.md).

## Quick start

```sh
make build
./bin/fastrecon -d example.com --stages enum

# With exclusions, as text.
./bin/fastrecon -d example.com --stages enum --format text \
  --exclude '*.dev.example.com' --exclude 're:^staging[0-9]*\.'

# Which sources exist, and which need a key.
./bin/fastrecon sources

# Enumerate, then split live hosts from dead ones.
./bin/fastrecon -d example.com --stages resolve --format text

# Bring your own resolver pool, from a file or a URL.
./bin/fastrecon -d example.com --stages resolve --resolvers-file ./resolvers.txt

# Enumerate, resolve, then scan the web ports of the live hosts.
./bin/fastrecon -d example.com --stages ports --ports web --format text

# The whole pipeline, ending with HTTP service detection.
./bin/fastrecon -d example.com --stages full --format text

# Serve the same pipeline over HTTP.
./bin/fastrecon serve --api-token "$TOKEN"
curl -H "Authorization: Bearer $TOKEN" \
  -d '{"domain":"example.com","stages":"enum"}' localhost:8080/run

# POST the report to an internal API instead of writing it anywhere.
./bin/fastrecon -d example.com --output "" \
  --webhook-url https://internal.example.net/hooks/recon \
  --webhook-header "Authorization: Bearer $TOKEN"
```

The default resolver pool is small and deliberate: Cloudflare, Google and
Quad9's unfiltered endpoints. Large public lists are supported but are the
wrong tool for this workload — see `SPECIFICATIONS.md` §8, which has the
measurements.

```sh
# Same thing, containerised.
make docker
docker run --rm -e CHAOS_API_KEY fastrecon:dev -d example.com --stages enum
```

## Configuration

Every option is settable three ways, and the names are mechanically related:

| | |
|---|---|
| flag | `--scan-mode connect` |
| environment | `FASTRECON_SCAN_MODE=connect` |
| config file | `scan-mode: connect` |

Precedence is `flag > environment > config file > default`. Run
`fastrecon --help` for the full list, which is generated from the flag
definitions and is therefore always current.

Report formats: `json` (indented, the default), `json-compact` (the same
document on one line, for log sinks), `jsonl` (one host per line), and `text`.

The scope of a run is one value:

```sh
fastrecon -d example.com --stages enum     # enumeration only
fastrecon -d example.com --stages resolve  # + live/dead separation
fastrecon -d example.com --stages ports    # + port scan
fastrecon -d example.com --stages full     # + HTTP probe (default)
```

## Credentials

API keys are never baked into the image. Provide them at runtime, in this order
of precedence:

1. `FASTRECON_KEY_<SOURCE>` — the namespaced environment variable,
2. `<SOURCE>_API_KEY` — the upstream spelling (`CHAOS_API_KEY`, …),
3. a provider config file mounted into the container, pointed at with
   `--provider-config` (subfinder/subfaster format),
4. `FASTRECON_KEY_<SOURCE>_FILE` — a path to a file holding the key, for
   Docker and Kubernetes secret mounts.

The default sources are `chaos`, `securitytrails`, `c99` (all key-required),
plus `submd` and `crt` which work without one. A run with no credentials at all
still returns data from the last two; the others are reported as
`skipped_no_key` rather than silently dropped.

Credential values never appear in the logs or the report. Error messages are
scrubbed, including request URLs — some sources put the key in the query
string.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | run completed, report emitted |
| 1 | invalid configuration or usage |
| 2 | report emitted, but the run did not finish its scope |
| 3 | report produced, at least one destination failed |
| 4 | fatal error, no report produced — including a transient failure such as an unreachable resolver list |

## Development

```sh
make test    # go test -race ./...
make lint    # golangci-lint
make cover   # coverage summary
make static  # assert the binary is still statically linked
```

`make static` is not optional busywork: the runtime image is
`distroless/static`, which has no dynamic loader. A dependency that reaches
libc through `dlopen` produces a binary that builds fine, passes every test,
and then fails at `exec` inside the container. CI runs the same check.
