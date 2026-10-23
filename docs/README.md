# FastRecon documentation

Read in order for a tour, or jump to the one you need.

| | |
|---|---|
| [00 — Overview](00-overview.md) | what FastRecon is, the pipeline, where it runs, what it is not |
| [01 — Usage](01-usage.md) | install, a first run, scopes, scanning a known list |
| [02 — Configuration](02-configuration.md) | precedence, time budget, exclusions, ports, resolvers, sources, API keys |
| [03 — Output](03-output.md) | formats, sinks, the report, how to read it, exit codes |
| [04 — Deployment](04-deployment.md) | Scaleway jobs, `fastrecon serve`, containers, sizing |
| [05 — Design notes](05-design.md) | why it is built this way, what was rejected, how to work on it |

The full option list is `fastrecon --help`. It is generated from the flag definitions, so it
is the one listing that cannot drift from the binary, and these docs do not repeat it.
