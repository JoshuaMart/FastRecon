# 01 — Usage

## Install

The published image is the shortest path, and it is what the serverless deployments run:

```sh
docker run --rm ghcr.io/joshuamart/fastrecon:main -d example.com --stages enum
```

CI publishes `main` (moving), `sha-<commit>` (immutable) and semver tags. **There is no
`latest`.** Pin a `sha-` tag for anything scheduled — a job that silently changes behaviour
between two CRON firings is hard to explain afterwards. The package is public, so no
registry credentials are needed.

From source:

```sh
make build
./bin/fastrecon -d example.com --stages full --format text
```

The binary is statically linked and depends on nothing at runtime.

## A first run

```sh
fastrecon -d example.com --stages full --ports web --format text
```

No API key is required to start: two of the five default sources work without one, so a
first run returns data immediately. Adding keys widens it — see
[Credentials](02-configuration.md#credentials).

## Choosing a scope

`--stages` takes one value, and each rung implies the ones below it.

| `--stages` | Runs | Sends to the target |
|---|---|---|
| `enum` | enumeration + exclusions | nothing |
| `resolve` | + DNS resolution | nothing |
| `ports` | + port scan | TCP connections |
| `full` | + HTTP probe (default) | TCP + HTTP requests |

`enum` and `resolve` are entirely passive from the target's point of view: the sources and
the DNS resolvers are third parties. `enum` performs no DNS query at all beyond what the
passive sources make themselves.

Arbitrary combinations are deliberately not expressible — see
[Why a ladder and not a set](05-design.md#why-a-ladder-and-not-a-set).

## Scanning a known list

Enumeration answers "what exists". It cannot answer "what still answers": if a source rate
limits, hosts vanish from the report while nothing changed on the target, and a resolve over
that output would call them dead.

For verification, supply the hosts instead:

```sh
fastrecon --targets-file ./inventory.txt --stages resolve
fastrecon --targets api.example.com --stages full          # single host, no source queried
fastrecon --targets-url https://internal/hosts --targets-header "Authorization: Bearer $T"
```

- The endpoint returns `text/plain`, one host per line. Blank lines and `#` comments are
  ignored; a host carrying a scheme, a path or a port is an error, not something to strip.
- A list **replaces** enumeration, it does not skip the stage — exclusions still apply.
- `-d/--domain` becomes optional and only labels the report.
- The root filter does not apply: a verification list legitimately spans several apexes of
  one perimeter.
- `run.input` says which input was used (`domain` or `targets`), and in targets mode
  `sources` is empty while `stats.enumerated` counts the supplied hosts.
- A malformed or over-large list **fails the run** rather than scanning a shortened one.

The reasoning is in [Why a target list exists](05-design.md#why-a-target-list-exists).

## Restricting what gets touched

Exclusions are applied before any network activity reaches a host:

```sh
--exclude 'admin.example.com'            # exact
--exclude '*.dev.example.com'            # everything under dev
--exclude 're:^staging[0-9]*\.'          # regexp
--exclude-file ./out-of-scope.txt        # one per line, # comments
```

A pattern that matches nothing is reported as a warning — a typo in an exclusion means hosts
were scanned that should not have been. Full rules, including the environment-variable form,
are in [Exclusions](02-configuration.md#exclusions).

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

`--format json` gives the same run as a document: per-source accounting, the addresses each
port was found on, TLS certificates, detected technologies and redirect chains. See
[Output](03-output.md).

## Other commands

| | |
|---|---|
| `fastrecon --help` | the full option list, generated from the flag definitions |
| `fastrecon sources` | every source the engine knows, with its key requirement |
| `fastrecon version` | version, commit and build date |
| `fastrecon serve` | the same pipeline behind an authenticated HTTP endpoint — see [Deployment](04-deployment.md#fastrecon-serve) |

`fastrecon --help` is the only option listing that cannot fall out of step with the binary,
which is why it is not reproduced anywhere in these docs.
