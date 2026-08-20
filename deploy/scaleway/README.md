# Scaleway deployment

Both deployments run the **same image** published by CI. Nothing here is
FastRecon-specific configuration baked into an artifact — it is all job or
function definition.

## Serverless Job

A job is the right target for a full run: its timeout is generous enough for
the whole ladder, and it needs no inbound network.

```sh
IMAGE=ghcr.io/joshuamart/fastrecon:latest

scw jobs definition create \
  name=fastrecon \
  image-uri="$IMAGE" \
  cpu-limit=1000 \
  memory-limit=2048 \
  timeout=30m \
  command="-d example.com --stages full --output /dev/stdout" \
  environment-variables.FASTRECON_ENVIRONMENT=serverless-job \
  environment-variables.FASTRECON_EXCLUDE='*.dev.example.com,admin.example.com' \
  environment-variables.FASTRECON_LOG_FORMAT=json
```

Credentials are set as job environment variables, ideally backed by Secret
Manager, never as build arguments:

```sh
scw jobs definition update <definition-id> \
  environment-variables.CHAOS_API_KEY=... \
  environment-variables.SECURITYTRAILS_API_KEY=... \
  environment-variables.C99_API_KEY=...
```

### Getting the results out

The job's stdout is collected as logs (Cockpit). That is fine for reading a run
and for `--format text`, but it is a log stream, not an artifact another system
can fetch. A job that has to hand its results to something else posts them:

```sh
scw jobs definition update <definition-id> \
  environment-variables.FASTRECON_OUTPUT="" \
  environment-variables.FASTRECON_WEBHOOK_URL=https://internal.example.net/hooks/recon \
  environment-variables.FASTRECON_WEBHOOK_HEADER='Authorization: Bearer ...'
```

`FASTRECON_OUTPUT=""` turns off the stdout sink so the report exists only where
it was sent. Leave it set to `-` to keep a copy in the logs as well — and if you
do, set `FASTRECON_FORMAT=json-compact`. The default indented format turns one
report into hundreds of log lines (a 75-host run produced 1889), which the
collector may reorder or drop; one line carries the same document intact.

Stopping a job sends SIGTERM. FastRecon cancels the run, marks the report
incomplete, and still delivers it: delivery runs on its own deadline, taken
from the share of the budget reserved by `--output-margin`.

### Scheduling

```sh
scw jobs definition update <definition-id> cron.schedule="0 3 * * *" cron.timezone=Europe/Paris
```

## Serverless Function

The function deployment is container-based: the same image, started with the
`serve` subcommand. It exists for short, bounded runs — `--stages enum` or
`resolve` on a known scope. Anything that needs the full ladder belongs in a
job, because a function's timeout is the tightest of the four environments and
work does not survive the response being returned.

```sh
scw function create \
  name=fastrecon \
  runtime=docker \
  registry-image="$IMAGE" \
  memory-limit=2048 \
  timeout=900s \
  environment-variables.FASTRECON_ENVIRONMENT=serverless-function \
  environment-variables.FASTRECON_SOURCES=chaos,securitytrails,c99,submd,crt \
  secret-environment-variables.FASTRECON_API_TOKEN=...
```

The container is started with the `serve` argument. Deploy it with a
**per-instance concurrency of 1**: the enumeration engine keeps per-run state on
globally shared instances, so a second concurrent request on one instance is
refused with `429` rather than corrupting both runs. Scale by adding instances,
not by sharing one.

Calling it:

```sh
curl -X POST "$FUNCTION_URL/run" \
  -H "Authorization: Bearer $FASTRECON_API_TOKEN" \
  -d '{"domain":"example.com","stages":"enum"}'
```

The request says what to scan, never how the function is wired: credentials,
sources, resolvers and any webhook destination come from the function's
environment. An unknown field in the body is rejected rather than ignored, so a
caller who believes they configured something is told they did not.

`fastrecon serve` refuses to start without `FASTRECON_API_TOKEN`.

## Notes

- Both deployments run unprivileged. The port scan therefore uses connect mode;
  `--scan-mode syn` needs `CAP_NET_RAW` and will refuse to run here rather than
  silently reporting zero open ports.
- Set `FASTRECON_ENVIRONMENT` explicitly. A serverless job and a plain
  container are indistinguishable from inside the process, so the label in the
  report comes from the deployment, not from a guess.
