# 01 — Usage

## Install

The published image is what the serverless deployments run:

```sh
docker run --rm ghcr.io/joshuamart/fastrecon:main -d example.com --stages enum
```

There is no `latest` tag; pin a `sha-` tag for anything scheduled
([image tags](04-deployment.md#choosing-an-image-tag)). From source:

```sh
make build
./bin/fastrecon -d example.com --stages full --format text
```

The binary is static and depends on nothing at runtime.

## A first run

```sh
fastrecon -d example.com --stages full --ports web --format text
```

No API key is required: `crt` works without one, so a first run returns data. Keys widen the
enumeration — see [Credentials](02-configuration.md#credentials).

## Choosing a scope

`--stages` takes one value, and each rung includes the ones below it.

| `--stages` | Runs | Sends to the target |
|---|---|---|
| `enum` | enumeration + exclusions | nothing |
| `resolve` | + DNS resolution | nothing |
| `ports` | + port scan | TCP connections |
| `full` | + HTTP probe (default) | TCP + HTTP requests |

`enum` and `resolve` talk only to third parties (the sources and the DNS resolvers); `enum`
makes no DNS query of its own. Arbitrary combinations are
[deliberately not expressible](05-design.md#why-a-ladder-and-not-a-set).

## Scanning a known list

Enumeration says what exists, not what still answers: when a source rate-limits, hosts
vanish from its output while nothing changed on the target, and a resolve would call them
dead. To verify a perimeter, supply the hosts:

```sh
fastrecon --targets-file ./inventory.txt --stages resolve
fastrecon --targets api.example.com --stages full          # one host, no source queried
fastrecon --targets-url https://internal/hosts --targets-header "Authorization: Bearer $T"
```

- One host per line; blank lines and `#` comments are ignored. A host with a scheme, a path
  or a port is an error.
- A list **replaces** enumeration: exclusions still apply, `-d` becomes an optional label,
  and hosts may span several apexes.
- A malformed or over-large list **fails the run** rather than scanning part of it.
- `--targets-url` accepts `http` and `https`. Headers over plain `http` log a warning (never
  the value), and a redirect that would carry them to another host or down to `http` is
  refused.
- `run.input` is `targets`, `sources` is empty, and `stats.enumerated` counts the list.

Background: [Why a target list exists](05-design.md#why-a-target-list-exists).

## Restricting what gets touched

Exclusions apply before any network activity reaches a host:

```sh
--exclude 'admin.example.com'            # exact
--exclude '*.dev.example.com'            # everything under dev
--exclude 're:^staging[0-9]*\.'          # regexp
--exclude-file ./out-of-scope.txt        # one per line, # comments
```

A pattern that matches nothing raises a warning, since it is usually a typo. Full rules:
[Exclusions](02-configuration.md#exclusions).

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
  dashboard.example.com                           live      80/http(308) 443/https(200)
  …
```

`--format json` gives the full document — see [Output](03-output.md).

## Other commands

| | |
|---|---|
| `fastrecon --help` | every option, generated from the flag definitions |
| `fastrecon sources` | every source the engine knows, with its key requirement |
| `fastrecon version` | version, commit and build date |
| `fastrecon serve` | the pipeline behind an authenticated HTTP endpoint — see [Deployment](04-deployment.md#fastrecon-serve) |
