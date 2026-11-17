# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Phase 2 control plane with initial JWT authentication and project ownership. Not an autonomous scanner.

## Implemented
- FastAPI backend and health endpoint.
- Password hashing with Argon2 and short-lived JWT access tokens.
- Registration, login, and current-user endpoints.
- User-owned projects; project, authorization, and target routes require authentication.
- Admin-only authorization review queue; approvals require explicit exact or wildcard hostname rules.
- Immutable scope snapshots bind a target to a reviewed authorization and store a SHA-256 integrity digest.
- Pre-dispatch validation checks snapshot integrity, target consistency, authorization status, expiry, and revocation.
- Admins can revoke active scope snapshots; snapshot creation never triggers network activity.
- DNS/IP destination policy rejects non-global answers and validates each redirect hop for future worker use; it returns addresses for pinning but does not open connections.
- Persistent scan jobs support authenticated enqueue/list/read/cancel. Enqueue revalidates scope and authorization; jobs remain queued with execution disabled.
- Explicit CLI script to provision/promote an administrator (no public admin registration).
- Audit events scoped to the acting user.
- SQLite local persistence and Alembic migration for legacy databases.
- Deterministic hostname allowlist check.

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

For local development the example JWT secret is intentionally marked as a placeholder. Never use it outside local development. Production mode refuses to start with the placeholder or a secret shorter than 32 characters.

## Authentication API
- `POST /api/v1/auth/register` — create a user (password minimum 12 characters).
- `POST /api/v1/auth/login` — receive a bearer access token.
- `GET /api/v1/auth/me` — inspect the authenticated user.

Send `Authorization: Bearer <access_token>` to protected endpoints.

## Administrator bootstrap
Run from `backend/` after installing dependencies and configuring the database:

```bash
SNAKE_BOOTSTRAP_ADMIN_EMAIL=admin@example.org SNAKE_BOOTSTRAP_ADMIN_PASSWORD='use-a-unique-password-of-16-chars-minimum' python scripts/bootstrap_admin.py
```

The script creates or promotes that account to `admin` and resets its password. Do not expose these environment values in logs or shell history. Admin review endpoints are `GET /api/v1/admin/authorizations/pending` and `POST /api/v1/admin/authorizations/{id}/review`.

## Project API
- `POST /api/v1/projects` and `GET /api/v1/projects`
- `POST /api/v1/projects/{id}/authorizations`
- `GET /api/v1/projects/{id}/authorizations`
- `POST /api/v1/projects/{id}/targets`
- `GET /api/v1/projects/{id}/targets`
- `GET /api/v1/audit`
- `POST /api/v1/scopes/check`
- `POST /api/v1/projects/{id}/targets/{target_id}/scope-snapshots`
- `GET /api/v1/projects/{id}/scope-snapshots`
- `GET /api/v1/scope-snapshots/{id}/validate`
- `POST /api/v1/scope-snapshots/{id}/scan-jobs` — create a queued, non-executing job (currently `passive_recon` profile only).
- `GET /api/v1/projects/{id}/scan-jobs` and `GET /api/v1/scan-jobs/{id}`
- `POST /api/v1/scan-jobs/{id}/cancel` — cancel a queued job.
- Admin: `POST /api/v1/admin/scope-snapshots/{id}/revoke`

Authorization records remain `pending`. Registering a target does not perform network activity or authorize a scan.

## Known limitations
This is not production-ready. Registration is open and has no email verification or rate limiting. JWT revocation/refresh, team roles, strict tenant-level audit retention, socket-level IP pinning, dispatch-time and request-time revalidation, worker isolation, and scanning are not implemented. Authorization approval is a manual record review only. The DNS helper is not a firewall and does not itself pin sockets. Jobs are database records only: there is no queue consumer, worker, or scanner, and no outbound scan traffic is generated. Keep the API private until these controls are completed.

See [architecture](docs/ARCHITECTURE.md) and [roadmap](docs/ROADMAP.md).
