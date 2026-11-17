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
- HMAC-SHA256 task signing and signed validation acknowledgements; the isolated validator verifies signed stdin messages and returns signed stdout acknowledgements.
- Atomic queued-job reservation and durable one-time task receipt/consumption primitives. Internal only; not exposed over HTTP or connected to a worker.
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

For local development the example JWT secret is intentionally marked as a placeholder. Never use it outside local development. Production mode refuses to start with the placeholder or a secret shorter than 32 characters. To run the optional validator profile, also set a separate random `SNAKE_WORKER_SIGNING_SECRET` (at least 32 characters); never reuse the JWT secret.

## Current boundary
The worker container is a **validator only**. It reads one signed task message from stdin (maximum 64 KiB), verifies HMAC and expiry, returns a signed validation acknowledgement, and exits. It has no network, queue consumer, database receipt access, Docker socket, or scan adapter. A valid signature is not proof of authorization.

HMAC signing protects message integrity/authenticity only. Durable receipt primitives prevent duplicate reservation and repeated receipt consumption in the backend database, but are not yet connected to the isolated validator. Socket-level IP pinning, per-request scope checks, and real scanning remain unimplemented. Keep the API private; this is not production-ready.

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), [worker runtime](docs/WORKER_RUNTIME.md), [task authentication](docs/WORKER_TASK_AUTHENTICATION.md), and [replay protection](docs/WORKER_REPLAY_PROTECTION.md).
