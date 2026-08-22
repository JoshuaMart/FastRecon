# 04 — Deployment

Both deployments run the **same image** published by CI. Nothing here is FastRecon
configuration baked into an artifact — it is all job or container definition.

Every Serverless Job command below was run against a real account. The Serverless Containers
section is marked where it was not.

## Picking the product

| | |
|---|---|
| **Serverless Job** | the one-shot run: `fastrecon -d …`. Runs to completion, exit code, CRON. |
| **Serverless Container** | `fastrecon serve`: an HTTP endpoint, scaled by request. |

A one-shot run does not belong in a container: it would have to listen for something, and
its whole contract is the exit status, which only a job surfaces. A `--stages full` run is
also measured in minutes, which no request timeout accommodates.

## Choosing an image tag

CI publishes `main` (moving), `sha-<commit>` (immutable) and semver tags. **There is no
`latest`.** Pin a `sha-` tag for anything scheduled: a job that silently changes behaviour
between two CRON firings is hard to explain afterwards.

```sh
IMAGE=ghcr.io/joshuamart/fastrecon:main
```

The package is public, so no registry credentials are needed.

---

## Serverless Job

```sh
scw jobs definition create \
  name=fastrecon \
  project-id="$PROJECT_ID" \
  image-uri="$IMAGE" \
  cpu-limit=1000 \
  memory-limit=1024 \
  local-storage-capacity=1024 \
  job-timeout=45m \
  retry-policy.max-retries=0 \
  args.0="--stages" args.1="full" \
  args.2="-d"      args.3="example.com" \
  environment-variables.FASTRECON_ENVIRONMENT=serverless-job \
  environment-variables.FASTRECON_TIMEOUT=30m \
  environment-variables.FASTRECON_FORMAT=json-compact
```

Four things that are easy to get wrong:

- **`project-id` is not optional in practice.** The CLI falls back to your `default`
  project, which is rarely where the rest of a recon setup lives.
- **`job-timeout` needs a unit** (`45m`), and it is `job-timeout`, not `timeout`.
- **Arguments are indexed** (`args.0`, `args.1`, …). The older `command="…"` form is
  deprecated and does not split a single string into arguments.
- **`local-storage-capacity` is required**, even though FastRecon writes nothing to disk.

### Timeouts have to nest

`FASTRECON_TIMEOUT` must be **shorter** than `job-timeout`. FastRecon reserves a slice of its
own budget to build and deliver the report, so a run that runs long still produces a
truncated but valid document. If the platform's timeout fires first the process is killed
instead and there is no report at all — the one outcome the whole budgeting design exists to
avoid. The gap also has to cover the image pull and startup.

### Retries: leave them off

`retry-policy.max-retries=0` is deliberate. The platform retries on a non-zero exit and
cannot see *which* code it was, but FastRecon uses [five](03-output.md#exit-codes). Only
code 4 justifies a retry, and the platform cannot single it out. Turn retries on only if
duplicate runs and duplicate webhook deliveries are acceptable.

### Running it

```sh
scw jobs definition start "$DEFINITION_ID"
```

Arguments and environment can be overridden **for one run**, leaving the stored definition
generic:

```sh
scw jobs definition start "$DEFINITION_ID" \
  args.0="--stages" args.1="full" \
  args.2="-d"      args.3="example.com" \
  args.4="--ports" args.5="web"
```

Stopping a job sends SIGTERM. FastRecon cancels the run, marks the report incomplete —
without claiming a timeout, since somebody stopped it on purpose — and still delivers it:
delivery runs on its own deadline.

### Credentials

Job environment variables, ideally backed by Secret Manager, never build arguments:

```sh
scw jobs definition update "$DEFINITION_ID" \
  environment-variables.CHAOS_API_KEY=... \
  environment-variables.SECURITYTRAILS_API_KEY=... \
  environment-variables.C99_API_KEY=...
```

> `scw jobs definition update` **replaces** the whole environment map rather than merging
> into it — verified: updating with one variable left exactly that one, and the four already
> set were gone. Pass every variable you want to keep, every time, or this command wipes the
> configuration above along with anything else that was there.

### Getting the results out

stdout is collected as logs (Cockpit). That is fine for reading a run, but it is a log
stream, not an artifact another system can fetch. A job that has to hand its results to
something else posts them:

```sh
scw jobs definition update "$DEFINITION_ID" \
  environment-variables.FASTRECON_OUTPUT="" \
  environment-variables.FASTRECON_WEBHOOK_URL=https://internal.example.net/hooks/recon \
  environment-variables.FASTRECON_WEBHOOK_HEADER='Authorization: Bearer ...'
```

`FASTRECON_OUTPUT=""` turns off the stdout sink so the report exists only where it was sent.
Keep it at `-` to retain a copy in the logs — and if you do, set
`FASTRECON_FORMAT=json-compact`. The default indented format turns one report into hundreds
of log lines: a 75-host run produced **1889**, which a collector may reorder or drop.

`json-compact` cuts that to one line, but **Cockpit splits log lines at 16384 bytes**.
Measured: an 18488-byte report arrived as 16384 + 2104, and a 296 KB report from a 617-host
run arrived in 19 pieces. The split is clean and the pieces concatenate back into valid
JSON, but it is one more thing a consumer has to know. Under roughly 16 KiB — a scope of a
few dozen hosts — one line arrives whole.

So the logs remain a place to *read* a run, not a transport. Anything a machine consumes
should go to the webhook.

### Scheduling

```sh
scw jobs definition update "$DEFINITION_ID" \
  cron-schedule.schedule="0 3 * * *" \
  cron-schedule.timezone=Europe/Paris
```

---

## Sizing

The measured runs and their consumption graphs are in the
[README](../README.md#performance): at 1000 mvCPU and 1024 MB, a 75-subdomain
`--stages full --ports web` run peaked at 223 MiB and 0.59 vCPU — 4.6× memory headroom and
1.7× CPU headroom against that allocation — and a 617-subdomain one at 252 MiB.

The cost is dominated by fixed allocations, not by target size, until the enumeration
reaches five or six figures. Memory tracks the number of enumerated hosts, roughly
**50 MB + 1.2 KB per host + ~180 MB when the scope includes the HTTP probe** — measured
across targets from 30 to 750,000 subdomains, where enumeration alone reached 959 MB.

So size for the domain you actually point it at. A few thousand subdomains fit comfortably
in 512 MiB; six-figure ones do not. Under-allocating loses the entire run with no report,
which is worth more than the difference in resource-seconds.

Reading the numbers back needs a Cockpit token scoped `read_only_metrics` and
`read_only_logs`, in **the same project as the job**:

```sh
scw cockpit token create name=fastrecon-readonly project-id="$PROJECT_ID" \
  token-scopes.0=read_only_logs token-scopes.1=read_only_metrics
```

The secret is shown **once**. The metrics are `serverless_job_run:memory_usage_bytes` and
`serverless_job_run:cpu_usage_seconds_total:rate30s` on the project's metrics data source;
logs are queried with `{resource_type="serverless_job", job_definition_name="fastrecon"}`.

---

## `fastrecon serve`

The same pipeline behind an authenticated HTTP endpoint. One artifact, one code path: the
handler builds a run configuration and calls the pipeline the CLI calls.

```sh
fastrecon serve --api-token "$TOKEN"

curl -X POST localhost:8080/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"domain":"example.com","stages":"enum"}'
```

`POST /run` takes a bearer token; the body names a `domain` and, optionally, `exclude`,
`stages`, `ports` and `timeout`. Anything omitted falls back to the environment, so a
pre-configured deployment is called with `{"domain": "…"}` alone. The response is the
[report document](03-output.md#report-shape). `GET /healthz` needs no token, which is what
makes it usable as a platform probe.

| Status | Meaning |
|---|---|
| `200` | report produced — **including a partial one**, which says so in `completed` and `truncated_by_timeout` |
| `400` | malformed body, or a configuration the run rejected |
| `401` | missing or wrong token |
| `429` | a run is already in progress on this instance; `Retry-After` set |
| `500` | a transient failure of ours: no report produced |

Not every option can be checked before a stage is built — a port expression is parsed by the
scanner — so some caller mistakes surface once the run starts and still return `400`, with
the offending part named.

`serve` refuses to start without `FASTRECON_API_TOKEN`: an unauthenticated
subdomain-enumeration endpoint is free reconnaissance for whoever finds it, charged to your
API quotas. The token is compared in constant time, on top of whatever the platform
provides.

**The request says what to scan, never how the deployment is wired.** Credentials, the
source selection, the resolver pool and any webhook destination come from the environment,
and an unknown field is rejected rather than ignored — so a caller who believes they
configured something is told they did not. The reasoning, including why only one run happens
at a time per instance, is in
[What the request may not set](05-design.md#what-the-request-may-not-set).

Two more things this deployment does differently:

- **The request timeout is the binding constraint.** It is materially shorter than a job's,
  so a full five-stage run over a large scope will not fit. `enum` and `resolve` are what
  this deployment is for; `ports` and `full` are permitted and the caller owns the risk. The
  requested scope is never silently downgraded.
- **It builds no sinks** — the report is the response. A `--webhook-url` configured on the
  deployment is validated at startup and then never fires, which from the outside is
  indistinguishable from one that fires and is never received, so `serve` logs a warning
  about it at startup.

## Serverless Container

> Not yet deployed against a real account. The commands below follow the CLI schema but have
> not been run, unlike the job ones above.

```sh
scw container container create \
  namespace-id="$NAMESPACE_ID" \
  name=fastrecon \
  image="$IMAGE" \
  args.0=serve \
  port=8080 \
  mvcpu-limit=1000 \
  memory-limit-bytes=1073741824 \
  timeout=900s \
  max-scale=4 \
  scaling-option.concurrent-requests-threshold=1 \
  startup-probe.http.path=/healthz \
  liveness-probe.http.path=/healthz \
  environment-variables.FASTRECON_ENVIRONMENT=serverless-function \
  secret-environment-variables.FASTRECON_API_TOKEN=...
```

- `args.0=serve` is what selects serve mode; the image's entrypoint is the binary itself, so
  without it the container starts in one-shot mode and exits on a missing domain.
- **`scaling-option.concurrent-requests-threshold=1`** is the important one. The enumeration
  engine keeps per-run state on globally shared instances, so two runs in one process
  overwrite each other's API keys and report each other's statistics. A second concurrent
  request is refused with `429` rather than corrupting both, but that is a guard: scale by
  adding instances.
- `/healthz` needs no token, which is what makes it usable as a probe.

## Notes

- Both deployments run unprivileged. The port scan therefore uses connect mode;
  `--scan-mode syn` refuses to run rather than silently reporting zero open ports.
- Set `FASTRECON_ENVIRONMENT` explicitly. A serverless job and a plain container are
  indistinguishable from inside the process, so the label in the report comes from the
  deployment, not from a guess.
