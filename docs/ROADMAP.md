# SNAKE Roadmap

## Phase 1 — Foundation (current)
Repository layout, API skeleton, scope-policy primitive, dashboard shell, architecture docs.
Next: verify tests, add CI, define data model and authentication.

## Phase 2 — Control Plane
Projects, users, authorization evidence, target scopes, immutable scope snapshots, audit log, job state machine, rate limits, cancellation.

## Phase 3 — Scanner Engine
Isolated worker protocol and narrowly scoped passive discovery adapters. Re-check scope at dispatch and execution; enforce egress and resource ceilings.

## Phase 4 — AI Orchestration
Supervisor and specialist agents; structured proposals and tool contracts; model router, budget controls, traceability, and approval gates.

## Phase 5 — Intelligence
Evidence-backed RAG, methodology versioning, evaluation corpus, and review workflow. No automatic deployment of untested methodology changes.

## Phase 6 — Validation and Reporting
Safe validation library, reproducible evidence, severity rationale, exportable reports.

## Phase 7 — Production Hardening
Threat modeling, security testing of SNAKE itself, secrets management, backups, observability, deployment automation, and operational procedures.
