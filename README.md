# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Phase 2 control plane plus worker-security foundations. Not an autonomous scanner.

## Implemented
- FastAPI backend with Argon2 password hashing, JWT login, and current-user endpoint.
- User-owned projects and admin-reviewed authorization records; public registration cannot assign admin role.
- Immutable SHA-256 scope snapshots with revalidation of integrity, target identity, authorization status/window, revocation, and approved scope rules.
- DNS/IP destination policy rejects non-global answers and validates redirect hops for future use; it does not open connections or enforce egress.
- Persistent scan jobs with authenticated enqueue/list/read/cancel endpoints. Jobs remain queued with execution disabled.
- Strict worker task envelope with a fixed passive profile, expiry, and no arbitrary command fields.
- Database-backed dispatch validation gate that re-reads persisted ownership, linkage, authorization, and snapshot state before preparing a short-lived disabled envelope.
- Validation-only Docker worker image: non-root, read-only runtime, dropped capabilities, no-new-privileges, bounded resources, and no network.
- HMAC-SHA256 task signing and signed validation acknowledgements with unique per-worker secrets, worker-ID binding, and key-version IDs.
- Internal signed-task issuance pipeline revalidates scope and atomically reserves a queued job; signed acknowledgements are bound to the task receipt and consumed once. No HTTP transport or network delivery.
- GitHub Actions runs backend tests and builds the validation-only worker image.

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
API docs: http://127.0.0.1:8000/docs

For local development the example JWT secret is intentionally marked as a placeholder.
Never use it outside local development. Production mode refuses to start with the
placeholder or a secret shorter than 32 characters. The validator requires a
dedicated random secret, worker ID, and key ID. Provision a different secret for
every worker; never reuse the JWT secret.

## Current boundary

The worker container is a **validator only**. It reads one signed task message from
stdin (maximum 64 KiB), verifies HMAC, intended worker/key identity and expiry,
returns a signed validation acknowledgement, and exits. It has no network, queue
consumer, database receipt access, Docker socket, or scan adapter.

The backend internal pipeline revalidates and reserves a job before signing a
worker-bound task. Its acknowledgement verifier checks the expected worker and key
ID, signature, task ID, envelope digest, and time window before consuming the
receipt. This is not connected to a network transport or the isolated validator's
stdin/stdout process. Per-worker secrets are injected out of band; no key registry,
KMS, automated provisioning, or rotation exists yet. Socket-level IP pinning,
per-request scope checks, and real scanning remain unimplemented. Keep the API
private; this is not production-ready.

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md),
[worker runtime](docs/WORKER_RUNTIME.md), [task authentication](docs/WORKER_TASK_AUTHENTICATION.md),
and [replay protection](docs/WORKER_REPLAY_PROTECTION.md).
