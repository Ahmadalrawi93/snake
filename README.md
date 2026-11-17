# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Phase 2 control-plane foundation. This is not yet an autonomous scanner or exploitation product.

## Current capabilities
- FastAPI backend and health endpoint.
- Deterministic hostname allowlist check.
- SQLite-backed project, authorization-record, and target registry.
- Audit events for project, authorization, and target registration.
- Next.js dashboard shell.

## Backend quick start
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

## Control-plane endpoints
- `POST /api/v1/projects` and `GET /api/v1/projects`
- `POST /api/v1/projects/{id}/authorizations`
- `GET /api/v1/projects/{id}/authorizations`
- `POST /api/v1/projects/{id}/targets`
- `GET /api/v1/projects/{id}/targets`
- `GET /api/v1/audit`
- `POST /api/v1/scopes/check`

Authorization records are created with `pending` status. Recording a URL or a target does not prove authorization and does not enable scanning. There is deliberately no endpoint to activate scanning or execute tools yet.

## Safety and known limitations
This is an early foundation, not production-ready. It currently has no user authentication, authorization-review workflow, database migrations, immutable scope snapshots, IP/redirect re-validation, rate limiting, worker isolation, or active scanner. Do not expose this API publicly or use it to scan targets.

See [architecture](docs/ARCHITECTURE.md) and [roadmap](docs/ROADMAP.md).
