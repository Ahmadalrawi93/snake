# SNAKE Architecture

## Intended system
- Next.js dashboard for projects, targets, jobs, findings, reports, and audit history.
- FastAPI control plane for identity, authorization, scope, job lifecycle, and policy.
- LangGraph (candidate) orchestration for supervised specialist agents.
- PostgreSQL for durable production records; pgvector for reviewed knowledge retrieval.
- Redis for queueing and coordination.
- Isolated workers for scanner adapters; local Kali worker and optional cloud worker.
- Model router selects providers by task, quality, latency, and budget.

## Current Phase 2 implementation
- FastAPI routes for project creation/listing.
- Authorization evidence records with a `pending` state.
- Target registration/listing; registration does not initiate network activity.
- SQLite persistence for local development.
- Audit events for project, authorization-record, and target creation.
- Existing hostname allowlist check.

## Trust boundaries and limitations
1. Authorization is an explicit record, never inferred by an LLM. Current records are pending and are not yet independently verified.
2. Scope policy is deterministic. Current hostname allowlist is configuration-based and is not yet bound to a reviewed authorization record.
3. Redirect destinations and resolved IPs must be checked before any future network access.
4. Worker egress must be restricted; model-generated strings must never be executed as shell commands.
5. Intrusive, destructive, or state-changing actions require human approval.
6. Evidence and decisions must be audited with tamper-resistant retention.
7. Secrets stay outside prompts and source control.
8. The current API has no authentication or tenant isolation and must remain local/private.

## Not implemented
Production authentication, role-based access, authorization approval workflow, database migrations, immutable scope snapshots, rate limiting, scanner, agents, queue, worker isolation, and production deployment.
