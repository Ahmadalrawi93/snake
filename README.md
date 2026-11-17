# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Phase 1 foundation. This is not yet an autonomous scanner or exploitation product.

## Principles
- Written authorization and explicit target scope are mandatory.
- Deterministic policy—not an LLM—decides whether an action is allowed.
- Discovery and validation are separated; intrusive checks require approval.
- Every task must be auditable and evidence-backed.

## Repository
- `backend/`: FastAPI control-plane foundation and scope policy.
- `frontend/`: Next.js dashboard shell.
- `agents/`, `scanner/`, `intelligence/`: contracts and future modules.
- `docs/`: architecture and roadmap.
- `infrastructure/`: local container setup.

## Backend quick start
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

## Safety
The current scope endpoint checks hostnames against a configured allowlist. It does not prove legal authorization. Do not connect active scanners until authorization records, scope snapshots, redirect/IP re-validation, rate limits, worker egress restrictions, audit logs, and approval gates are implemented.

See [ROADMAP](docs/ROADMAP.md). No real reconnaissance, exploitation, or autonomous scanning is implemented yet.
