# FastRecon

Attack-surface discovery for a domain: passive subdomain enumeration, exclusion
filtering, live/dead separation, port scanning, and HTTP probing — as a single
static binary that runs the same way locally, in Docker, in a serverless job,
and behind a serverless function.

The design is specified in **[SPECIFICATIONS.md](SPECIFICATIONS.md)**. Read that
first; this file is only the quick start.

## Status

Phase 1 of 8 — the skeleton. What works today:

- the CLI, with the full option surface and its precedence rules
  (flag > environment > config file > default),
- the run report model and its `json` / `jsonl` / `text` renderings,
- the stdout and file sinks,
- pipeline orchestration: the stage ladder, deadline budgeting, truncation
  handling, and exit codes,
- the container image and CI.

The recon stages themselves land in phases 2–5. Until then a run walks the
ladder, reports that the enumeration stage has no implementation, and exits 2 —
it does not pretend to have found nothing.

## Quick start

```sh
make build
./bin/fastrecon -d example.com --stages enum
```

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

The scope of a run is one value:

```sh
fastrecon -d example.com --stages enum     # enumeration only
fastrecon -d example.com --stages resolve  # + live/dead separation
fastrecon -d example.com --stages ports    # + port scan
fastrecon -d example.com --stages full     # + HTTP probe (default)
```

## Credentials

API keys are never baked into the image. Provide them at runtime as
environment variables (`CHAOS_API_KEY`, `SECURITYTRAILS_API_KEY`, `C99_API_KEY`,
or the namespaced `FASTRECON_KEY_*` form), or as a provider config file mounted
into the container and pointed at with `--provider-config`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | run completed, report emitted |
| 1 | invalid configuration or usage |
| 2 | report emitted, but the run did not finish its scope |
| 3 | report produced, at least one destination failed |
| 4 | fatal error, no report produced |

## Development

```sh
make test    # go test -race ./...
make lint    # golangci-lint
make cover   # coverage summary
```
