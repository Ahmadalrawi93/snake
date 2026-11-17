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
- Internal issuance revalidates scope and reserves jobs once; acknowledgement verification binds the worker key and durable receipt.
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
only the backend public key and its own private key; the backend receives that
worker's public key. Never reuse a worker keypair across workers. Key provisioning,
revocation, and rotation are not automated yet.

The validator reads one signed message from stdin and emits a signed validation
acknowledgement. It has no network, database receipt access, queue consumer, or
scan adapter. This is not production-ready. Socket-level IP pinning, per-request
scope checks, egress enforcement, real transport, and scan execution remain
unimplemented.

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md),
[worker runtime](docs/WORKER_RUNTIME.md),
[task authentication](docs/WORKER_TASK_AUTHENTICATION.md), and
[replay protection](docs/WORKER_REPLAY_PROTECTION.md).
