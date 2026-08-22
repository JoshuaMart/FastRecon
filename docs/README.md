# FastRecon documentation

Read in order for a tour, or jump straight to the one you need.

| | |
|---|---|
| [00 — Overview](00-overview.md) | what FastRecon is, the pipeline, where it runs, what it deliberately is not |
| [01 — Usage](01-usage.md) | install, a first run, choosing a scope, scanning a known list |
| [02 — Configuration](02-configuration.md) | flags, environment, exclusions, ports, resolvers, sources and API keys |
| [03 — Output](03-output.md) | formats, sinks, the report schema, how to read it, exit codes |
| [04 — Deployment](04-deployment.md) | `fastrecon serve`, Scaleway jobs and containers, sizing, scheduling |
| [05 — Design notes](05-design.md) | why it is built this way, what was rejected, and how to work on it |

The full flag list is `fastrecon --help`, generated from the flag definitions — the only
listing that cannot fall out of step with the binary, and therefore the one place it is not
duplicated here.
