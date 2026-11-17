# SNAKE Roadmap

## Phase 1 — Foundation (implemented scaffold)
Repository layout, FastAPI API, hostname allowlist primitive, dashboard shell, architecture docs, and CI workflow.

## Phase 2 — Control Plane (initial slice implemented)
- SQLite persistence models for projects, authorization records, targets, and audit events.
- Project creation/listing.
- Authorization evidence records default to `pending`; recording is not approval.
- Target registration/listing without network activity.
- Audit event listing.
- Remaining: authentication and roles, authorization review workflow, migrations, immutable scope snapshots, stronger audit integrity, and API-level tenant isolation.

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
