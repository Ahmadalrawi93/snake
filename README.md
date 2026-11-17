# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Phase 2 control plane with initial JWT authentication and project ownership. Not an autonomous scanner.

## Implemented
- FastAPI backend and health endpoint.
- Password hashing with Argon2 and short-lived JWT access tokens.
- Registration, login, and current-user endpoints.
- User-owned projects; project, authorization, and target routes require authentication.
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

## Project API
- `POST /api/v1/projects` and `GET /api/v1/projects`
- `POST /api/v1/projects/{id}/authorizations`
- `GET /api/v1/projects/{id}/authorizations`
- `POST /api/v1/projects/{id}/targets`
- `GET /api/v1/projects/{id}/targets`
- `GET /api/v1/audit`
- `POST /api/v1/scopes/check`

Authorization records remain `pending`. Registering a target does not perform network activity or authorize a scan.

## Known limitations
This is not production-ready. Registration is open and has no email verification or rate limiting. JWT revocation/refresh, roles and admin approval, strict tenant-level audit retention, migrations beyond the current schema step, immutable scope snapshots, IP/redirect re-validation, worker isolation, and active scanning are not implemented. Keep the API private until these controls are completed.

See [architecture](docs/ARCHITECTURE.md) and [roadmap](docs/ROADMAP.md).
