# Worker runtime security boundary

SNAKE does **not** have a scan worker or queue consumer yet. The opt-in
`worker-validator` Compose service is a deliberately non-executing runtime
prototype:

- It is disabled unless Compose is invoked with `--profile worker`.
- It runs as UID/GID 10001, drops all Linux capabilities, enables
  `no-new-privileges`, uses a read-only root filesystem, and has bounded
  memory, CPU, PID count, and temporary storage.
- `network_mode: none` disables container networking entirely. It has no
  published ports, Docker socket, host mounts, or application data volume.
- It accepts a single JSON envelope on stdin (maximum 64 KiB), validates the
  strict `WorkerTaskEnvelope`, checks expiry, emits a validation-only result,
  and exits. It has no shell command field and performs no scan or network I/O.

Example build (no task execution):
```sh
docker compose -f infrastructure/docker-compose.yml --profile worker build worker-validator
```

To run the validator, pipe a JSON envelope to `docker compose ... run --rm -T
worker-validator`. The envelope must be created by a trusted test harness.
A successful response means only that the metadata parsed and was not expired;
it is **not** proof of authorization and does not claim or execute a scan job.

Before introducing a real worker, SNAKE still needs authenticated internal
transport, atomic job claiming, replay protection, independent scope and
authorization revalidation at dispatch and immediately before each request,
DNS/IP pinning, redirect-hop validation, and a default-deny egress firewall.
The validator's `network_mode: none` is intentionally stricter than a future
network-enabled scanner worker and must not be mistaken for that future design.
