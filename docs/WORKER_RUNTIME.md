# Worker runtime security boundary

SNAKE does **not** have a scan worker or queue consumer yet. The opt-in
`worker-validator` Compose service is an authenticated, deliberately
non-executing protocol prototype:

- It is disabled unless Compose is invoked with `--profile worker`.
- It runs as UID/GID 10001, drops all Linux capabilities, enables
  `no-new-privileges`, uses a read-only root filesystem, and has bounded
  memory, CPU, PID count, and temporary storage.
- `network_mode: none` disables container networking entirely. It has no
  published ports, Docker socket, host mounts, or application data volume.
- It accepts one signed JSON task message on stdin (maximum 64 KiB), verifies
  the HMAC using the dedicated `SNAKE_WORKER_SIGNING_SECRET`, checks expiry,
  and emits a signed validation-only acknowledgement on stdout.
- The acknowledgement binds the task ID and canonical envelope digest, identifies
  the validator, and fixes `execution_enabled=false`. It cannot claim scan completion.

For local testing, set a dedicated random `SNAKE_WORKER_SIGNING_SECRET` of at
least 32 characters and optionally `SNAKE_WORKER_ID`. Never reuse the JWT
secret. The Compose variable is optional at configuration time, but the validator
refuses to run without a valid secret. Environment variables are a development
convenience, not a production secrets-management design.

Example build:
```sh
docker compose -f infrastructure/docker-compose.yml --profile worker build worker-validator
```

The validator is not connected to the backend database receipt ledger. It cannot
consume a task receipt or independently prevent replay across invocations. It has
no queue consumer, scan adapters, DNS resolution, or network I/O. A successful
acknowledgement proves only that the signed metadata was valid and unexpired; it
does not prove target authorization and does not execute a scan.

Before introducing a real network-enabled worker, SNAKE still needs authenticated
backend-to-worker transport, atomic receipt consumption integrated with dispatch,
authorization/scope revalidation immediately before each request, socket-level
DNS/IP pinning, redirect-hop enforcement, and a default-deny egress firewall.
