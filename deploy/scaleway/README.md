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
can fetch. A job that has to hand its results to something else sets
`FASTRECON_WEBHOOK_URL` and posts the report to an internal API — that sink
lands in phase 6.

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

This deployment lands with phase 8; `fastrecon serve` currently exits with a
usage error rather than starting a handler.

## Notes

- Both deployments run unprivileged. The port scan therefore uses connect mode;
  `--scan-mode syn` needs `CAP_NET_RAW` and will refuse to run here rather than
  silently reporting zero open ports.
- Set `FASTRECON_ENVIRONMENT` explicitly. A serverless job and a plain
  container are indistinguishable from inside the process, so the label in the
  report comes from the deployment, not from a guess.
