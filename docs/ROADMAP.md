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
- Explicit reviewed hostname rules are required for approval.
- Immutable SHA-256 scope snapshots bind targets to approved authorizations.
- Pre-dispatch validation checks hash, target drift, authorization state, expiry, and revocation; admins can revoke snapshots.
- Added a deterministic DNS/IP destination gate and redirect-hop validator for future workers; it rejects non-global addresses and returns IPs for connection pinning. This helper does not open sockets or enforce network egress.
- Added persistent scan-job records and authenticated create/list/read/cancel endpoints. Enqueue revalidates snapshot integrity, authorization, expiry, target drift, and hostname scope.
- Jobs remain `queued` records with `execution_enabled=false`; no queue consumer, worker, or scan execution exists.
- Remaining: email verification, registration throttling, refresh/revocation, team roles, immutable audit retention, socket-level IP pinning, dispatch-time and request-time revalidation, and isolated worker egress enforcement.

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


## Worker security boundary (current increment)
- [x] Strict worker task envelope with fixed profile, snapshot digest, expiry, and no arbitrary command fields.
- [x] Tests for unknown command fields, execution-enabled payloads, unsupported profiles, naive timestamps, and expired tasks.
- [ ] Dispatcher with database-backed revalidation at dispatch time.
- [ ] Isolated non-root container runtime with resource limits and default-deny egress.
- [ ] Socket-level destination pinning and redirect revalidation before every request.
- [ ] Passive recon adapters; no adapter is executable yet.

The worker protocol is a data contract only. No worker, dispatcher, network request, or scan execution is enabled.


## Dispatch validation gate
- [x] Re-read persisted job/project/target/snapshot/authorization before preparing a task.
- [x] Enforce job queued state, fixed passive profile, ownership/linkage, snapshot integrity and authorization validity.
- [x] Short-lived task expiry capped at five minutes and never beyond authorization/snapshot expiry.
- [x] Envelope remains execution-disabled; no job claim, worker contact, DNS lookup, or HTTP traffic.
- [ ] Atomic queue claim and replay protection.
- [ ] Authenticated worker transport and signed task/result messages.
