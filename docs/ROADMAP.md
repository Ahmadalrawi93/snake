# SNAKE Roadmap

## Phase 1 — Foundation
Repository structure, FastAPI service, hostname allowlist primitive, dashboard shell, architecture docs, and CI workflow.

## Phase 2 — Control Plane (initial implementation)
- SQLite models for users, projects, authorization records, targets, and audit events.
- Argon2 password hashing, JWT login, and current-user endpoint.
- User ownership enforced across project, target, and authorization APIs.
- Admin-only pending authorization queue and approve/reject review endpoint with audit events.
- Explicit CLI admin bootstrap; public registration cannot assign admin role.
- Explicit reviewed hostname rules are required for approval.
- Immutable SHA-256 scope snapshots bind targets to approved authorizations.
- Validation checks hash, target drift, authorization state, expiry, revocation, and approved-rule drift.
- DNS/IP destination policy rejects non-global addresses and validates redirect hops; it does not open sockets or enforce egress.
- Persistent scan-job records and authenticated create/list/read/cancel endpoints.
- Jobs remain queued with execution disabled; no queue consumer or scan execution exists.

## Phase 3 — Scanner Engine
- [x] Strict worker task envelope with fixed profile, snapshot digest, expiry, and no arbitrary command fields.
- [x] Database-backed dispatch validation gate re-reads persisted job/project/target/snapshot/authorization state.
- [x] Short-lived task envelope capped at five minutes and authorization/snapshot expiry.
- [x] Validation-only container image: non-root user, read-only root filesystem at runtime, all capabilities dropped, no-new-privileges, bounded CPU/memory/PIDs/tmpfs, and no network.
- [x] HMAC-SHA256 task-envelope and validation-acknowledgement signing with constant-time verification.
- [x] Isolated stdin/stdout validator verifies signed tasks and returns signed validation-only acknowledgements (not connected to backend receipt ledger).
- [x] Atomic queued-job reservation and durable one-time receipt/consumption primitives (internal only; not connected to a worker).
- [ ] Authenticated backend-to-worker transport with receipt consumption integrated into dispatch.
- [ ] DNS/IP pinning and redirect-hop enforcement at the actual socket/request layer.
- [ ] Passive recon adapters and isolated worker execution. No scanner is executable yet.

## Phase 4 — AI Orchestration
Supervisor and specialist agents; structured proposals and tool contracts; model router, budget controls, traceability, and approval gates.

## Phase 5 — Intelligence
Evidence-backed RAG, methodology versioning, evaluation corpus, and review workflow. No automatic deployment of untested methodology changes.

## Phase 6 — Validation and Reporting
Safe validation library, reproducible evidence, severity rationale, exportable reports.

## Phase 7 — Production Hardening
Threat modeling, security testing of SNAKE itself, secrets management, backups, observability, deployment automation, and operational procedures.

## Explicit safety boundary
All current worker components are preparatory only. The validator container accepts a signed JSON task, verifies its signature and expiry, returns a signed validation acknowledgement, and exits. It cannot reach a network, consume a backend receipt, claim a job, or execute a scan. HMAC signing protects integrity/authenticity only; it does not provide authorization or scope enforcement. Atomic receipt primitives exist but are not wired to a worker or HTTP route. No scan execution is enabled.
