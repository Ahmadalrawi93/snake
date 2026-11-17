# Worker runtime security boundary

SNAKE does not yet have a scan worker or queue consumer. The opt-in worker-validator
Compose service is an authenticated, deliberately non-executing protocol prototype.

- Runs as UID/GID 10001 with dropped capabilities, no-new-privileges, read-only
  root filesystem, bounded resources, and network_mode: none.
- Accepts one signed JSON task on stdin (maximum 64 KiB), verifies the backend's
  Ed25519 signature using a public key, validates worker/key binding and expiry,
  then emits a signed validation-only acknowledgement.
- The worker signs acknowledgements using its own Ed25519 private key. The backend
  verifies with the corresponding public key. The worker never receives the
  backend private key.
- It has no DB, network, queue consumer, scan adapter, Docker socket, or host mount.

Provision a distinct keypair for every worker. Inject only the backend public key
and that worker's private key into its runtime. Keep the backend private key in
backend-only secret storage; configure the worker public key on the backend.
Environment variables are for development, not a production secret-management
solution. No key registry, KMS integration, automated provisioning, revocation,
or rotation workflow exists yet.

Example build:
```sh
docker compose -f infrastructure/docker-compose.yml --profile worker build worker-validator
```

A valid acknowledgement proves only that the holder of the worker private key
signed the validation metadata. It does not prove a scan ran or that a target
was authorized. Replay protection remains backend receipt-based and is not
end-to-end connected to this isolated process. Network transport and scan
execution remain disabled.
