# Worker runtime security boundary

SNAKE does **not** have a scan worker or queue consumer yet. The opt-in
worker-validator Compose service is an authenticated, deliberately
non-executing protocol prototype:

- It is disabled unless Compose is invoked with --profile worker.
- It runs as UID/GID 10001, drops all Linux capabilities, enables
  no-new-privileges, uses a read-only root filesystem, and has bounded
  memory, CPU, PID count, and temporary storage.
- network_mode: none disables container networking entirely. It has no
  published ports, Docker socket, host mounts, or application data volume.
- It accepts one signed JSON task message on stdin (maximum 64 KiB), verifies
  the HMAC using its own dedicated secret, checks worker ID and key ID binding,
  checks expiry, then emits a signed validation-only acknowledgement on stdout.
- The acknowledgement binds the task ID and canonical envelope digest, identifies
  the validator, includes the key ID, and fixes execution_enabled=false.

For local testing, configure a unique random SNAKE_WORKER_SIGNING_SECRET
(at least 32 characters), SNAKE_WORKER_ID, and SNAKE_WORKER_KEY_ID for this worker.
Every other worker must use a different secret. Never reuse the JWT secret.
Environment variables are a development convenience, not a production
secrets-management design.

The backend signing functions accept an explicitly selected worker secret and key ID.
The operator must provision the same unique secret to the backend's trusted
configuration and that worker's runtime out of band. There is not yet a backend
worker-key registry, KMS integration, automated rotation, or provisioning API.

Example build:
```sh
docker compose -f infrastructure/docker-compose.yml --profile worker build worker-validator
```

The validator is not connected to the backend database receipt ledger. It cannot
consume a task receipt or independently prevent replay across invocations. It has
no queue consumer, scan adapters, DNS resolution, or network I/O. A successful
acknowledgement proves only that signed metadata was valid and unexpired; it does
not prove target authorization and does not execute a scan.

Before introducing a real network-enabled worker, SNAKE still needs authenticated
backend-to-worker transport, atomic receipt consumption integrated with dispatch,
authorization/scope revalidation immediately before each request, socket-level
DNS/IP pinning, redirect-hop enforcement, and a default-deny egress firewall.
