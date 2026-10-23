# 04 — Deployment

Every deployment runs the **same image** published by CI; everything below is job or
container definition. The Serverless Job commands were run against a real account; the
Serverless Container section says where it was not.

## Picking the product

| | |
|---|---|
| **Serverless Job** | the one-shot run, `fastrecon -d …`: runs to completion, exit code, CRON |
| **Serverless Container** | `fastrecon serve`: an HTTP endpoint, scaled by request |

A one-shot run does not belong in a container: its contract is the exit status, which only a
job surfaces, and a `full` run takes minutes, which no request timeout allows.

## Choosing an image tag

CI publishes `main` (moving), `sha-<commit>` (immutable) and semver tags. **There is no
`latest`.** Pin a `sha-` tag for anything scheduled: a job that changes behaviour between two
CRON firings is hard to explain. The package is public; no registry credentials are needed.

```sh
IMAGE=ghcr.io/joshuamart/fastrecon:main
```

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

Easy to get wrong:

- **`project-id`**: without it the CLI uses your `default` project.
- **`job-timeout`** (not `timeout`) needs a unit: `45m`.
- **Arguments are indexed** (`args.0`, `args.1`, …). The deprecated `command="…"` does not
  split a string into arguments.
- **`local-storage-capacity` is required**, even though FastRecon writes nothing to disk.

### Timeouts have to nest

`FASTRECON_TIMEOUT` must be **shorter** than `job-timeout`, with room for the image pull and
startup. FastRecon keeps part of its budget to deliver a truncated report; if the platform's
timeout fires first, the process is killed and there is no report at all.

### Retries: leave them off

The platform retries on any non-zero exit and cannot tell FastRecon's
[five exit codes](03-output.md#exit-codes) apart; only code 4 deserves a retry. Keep
`retry-policy.max-retries=0` unless duplicate runs and webhook deliveries are acceptable.

### Running it

```sh
scw jobs definition start "$DEFINITION_ID"
```

Arguments and environment can be overridden for **one run**, leaving the definition generic:

```sh
scw jobs definition start "$DEFINITION_ID" \
  args.0="--stages" args.1="full" \
  args.2="-d"      args.3="example.com" \
  args.4="--ports" args.5="web"
```

Stopping a job sends SIGTERM: the run is cancelled, the report marked incomplete (without
claiming a timeout), and still delivered.

### Credentials

Job environment variables, ideally backed by Secret Manager — never build arguments:

```sh
scw jobs definition update "$DEFINITION_ID" \
  environment-variables.CHAOS_API_KEY=... \
  environment-variables.SECURITYTRAILS_API_KEY=... \
  environment-variables.C99_API_KEY=...
```

> `scw jobs definition update` **replaces** the whole environment map — verified: updating
> one variable removed the four already set. Pass every variable you want to keep, every time.

### Getting the results out

stdout ends up in the logs (Cockpit): fine to read a run, not something another system can
fetch. To hand results on, post them:

```sh
scw jobs definition update "$DEFINITION_ID" \
  environment-variables.FASTRECON_OUTPUT="" \
  environment-variables.FASTRECON_WEBHOOK_URL=https://internal.example.net/hooks/recon \
  environment-variables.FASTRECON_WEBHOOK_HEADER='Authorization: Bearer ...'
```

`FASTRECON_OUTPUT=""` turns off stdout so the report exists only at the webhook. To keep a
copy in the logs, leave it at `-` with `FASTRECON_FORMAT=json-compact`: the indented format
turned a 75-host report into **1889** log lines, which a collector may reorder or drop.

Even compact, **Cockpit splits lines at 16384 bytes**: an 18488-byte report arrived as
16384 + 2104, a 296 KB one (617 hosts) in 19 pieces. They concatenate back into valid JSON,
but only reports under ~16 KiB — a few dozen hosts — arrive whole.

### Scheduling

```sh
scw jobs definition update "$DEFINITION_ID" \
  cron-schedule.schedule="0 3 * * *" \
  cron-schedule.timezone=Europe/Paris
```

---

## Sizing

Measured runs and graphs are in the [README](../README.md#performance): at 1000 mvCPU and
1024 MB, a 75-subdomain `--stages full --ports web` run peaked at 223 MiB and 0.59 vCPU, a
617-subdomain one at 252 MiB.

Memory tracks the number of enumerated hosts, roughly **50 MB + 1.2 KB per host, plus
~180 MB when the scope includes the HTTP probe** — measured from 30 to 750,000 subdomains,
where enumeration alone reached 959 MB. A few thousand subdomains fit in 512 MiB;
six-figure ones do not. Size for the domain you point it at: running out of memory loses the
run with no report.

Reading the numbers back needs a Cockpit token scoped `read_only_metrics` and
`read_only_logs`, in **the job's project**:

```sh
scw cockpit token create name=fastrecon-readonly project-id="$PROJECT_ID" \
  token-scopes.0=read_only_logs token-scopes.1=read_only_metrics
```

The secret is shown **once**. Metrics: `serverless_job_run:memory_usage_bytes` and
`serverless_job_run:cpu_usage_seconds_total:rate30s`. Logs:
`{resource_type="serverless_job", job_definition_name="fastrecon"}`.

---

## `fastrecon serve`

The same pipeline behind an authenticated HTTP endpoint, built through the same code path as
the CLI.

```sh
fastrecon serve --api-token "$TOKEN"

curl -X POST localhost:8080/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"domain":"example.com","stages":"enum"}'
```

`POST /run` takes a `domain` and, optionally, `exclude`, `stages`, `ports` and `timeout`;
anything omitted comes from the environment. A request's `exclude` is **added** to the
deployment's exclusions, never substituted, so a caller cannot widen the scope. The response
is the [report](03-output.md#report-shape). `GET /healthz` needs no token, for platform
probes.

| Status | Meaning |
|---|---|
| `200` | report produced — **including a partial one**, which says so in `completed` and `truncated_by_timeout` |
| `400` | malformed body, or a configuration the run rejected (some, like a port expression, only once the run starts) |
| `401` | missing or wrong token |
| `429` | a run is already in progress on this instance; `Retry-After` set |
| `500` | a transient failure: no report produced |

- **`serve` refuses to start without `FASTRECON_API_TOKEN`**: an open endpoint is free
  reconnaissance for anyone, on your API quotas. The token is compared in constant time.
- **The request says what to scan, never how the deployment is wired**: credentials,
  sources, resolvers and destinations come from the environment, and an unknown field is
  rejected. Why, and why one run per instance:
  [What the request may not set](05-design.md#what-the-request-may-not-set).
- **The request timeout is the binding constraint.** `enum` and `resolve` are what this
  deployment is for; `ports` and `full` are allowed at the caller's risk, never downgraded.
- **No sinks**: the report is the response. A configured `--webhook-url` never fires, and
  `serve` warns about it at startup.

## Serverless Container

> Not yet run against a real account: the commands follow the CLI schema but are untested.

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

- `args.0=serve` selects serve mode; without it the container runs one-shot and exits on the
  missing domain.
- **`concurrent-requests-threshold=1`** matters: the enumeration engine keeps per-run state
  globally, so a second concurrent request gets a `429`. Scale with instances.

## Notes

- Both deployments run unprivileged, so the port scan uses connect mode.
- Set `FASTRECON_ENVIRONMENT` explicitly: a job and a plain container look the same from
  inside, so the report's label comes from the deployment.
