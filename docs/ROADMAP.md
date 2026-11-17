# SNAKE Roadmap

## Phase 1 — Foundation
Repository structure, FastAPI service, hostname allowlist primitive, dashboard shell, architecture docs, and CI workflow.

## Phase 2 — Control Plane (initial implementation)
- SQLite models for users, projects, authorization records, targets, and audit events.
- Argon2 password hashing, JWT login, and current-user endpoint.
- User ownership enforced across project, target, and authorization APIs.
- Audit listing scoped to the authenticated actor.
- Alembic migration for ownership columns on existing databases.
- Admin-only pending authorization queue and approve/reject review endpoint with audit events.
- Explicit CLI admin bootstrap; public registration cannot assign admin role.
- Remaining: email verification, registration throttling, refresh/revocation, team roles, immutable scope snapshots, and stronger audit integrity.

## Phase 3 — Scanner Engine
Isolated worker protocol and narrowly scoped passive discovery adapters. Re-check scope at dispatch and execution; enforce egress and resource ceilings. No arbitrary shell execution.

## Phase 4 — AI Orchestration
Supervisor and specialist agents; structured proposals and tool contracts; model router, budget controls, traceability, and approval gates.

## Phase 5 — Intelligence
Evidence-backed RAG, methodology versioning, evaluation corpus, and review workflow. No automatic deployment of untested methodology changes.

## Phase 6 — Validation and Reporting
Safe validation library, reproducible evidence, severity rationale, exportable reports.

## Phase 7 — Production Hardening
Threat modeling, security testing of SNAKE itself, secrets management, backups, observability, deployment automation, and operational procedures.
