# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Control plane and worker-security foundations. Not an autonomous scanner.

## Implemented
- FastAPI authentication, user-owned projects, and admin-reviewed authorization records.
- Immutable SHA-256 scope snapshots and scope revalidation before dispatch preparation.
- DNS/IP destination policy and redirect-hop validation foundations; no outbound requests.
- Persistent scan jobs that remain queued with execution disabled.
- Strict worker task envelope with a fixed passive profile, expiry, and no arbitrary commands.
- Validation-only Docker worker: non-root, read-only, resource-limited, and network-isolated.
- Ed25519 asymmetric authentication: backend signs tasks; each worker signs acknowledgements with its own keypair.
- Admin-only worker public-key registry with duplicate-key protection, fingerprinting, audit events, and one-way revocation.
- Internal issuance revalidates scope and reserves jobs once; acknowledgement verification resolves the active worker key from the registry and consumes the durable receipt once.
- No worker transport, queue consumer, or scan execution.

## Local setup
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

## Security boundary

The backend private signing key must never leave the backend. A worker receives
only the backend public key and its own private key. The backend stores the
worker's public key in the database registry; private keys are never stored there.
Administrators can register, list, and revoke worker public keys through the
admin API. Replacing a key requires a new key ID and keypair. KMS-backed storage,
automated provisioning, and automated rotation are not implemented.

The validator reads one signed message from stdin and emits a signed validation
acknowledgement. It has no network, database receipt access, queue consumer, or
scan adapter. This is not production-ready. Socket-level IP pinning, per-request
scope checks, egress enforcement, real transport, and scan execution remain
unimplemented.

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md),
[worker runtime](docs/WORKER_RUNTIME.md),
[task authentication](docs/WORKER_TASK_AUTHENTICATION.md), and
[replay protection](docs/WORKER_REPLAY_PROTECTION.md).
