# SNAKE Architecture

## Intended system
- Next.js dashboard for projects, targets, jobs, findings, reports, and audit history.
- FastAPI control plane for identity, authorization, scope, job lifecycle, and policy.
- LangGraph (candidate) orchestration for supervised specialist agents.
- PostgreSQL for durable production records; pgvector for reviewed knowledge retrieval.
- Redis for queueing and coordination.
- Isolated workers for scanner adapters; local Kali worker and optional cloud worker.
- Model router selects providers by task, quality, latency, and budget.

## Current implementation
- FastAPI project and target registry with SQLite persistence.
- Argon2 password hashing and JWT bearer authentication.
- Project ownership checked on project, authorization, and target operations.
- User-scoped audit event listing.
- Admin-only authorization review queue and approve/reject endpoint; decisions are audited.
- Admin account provisioning is an explicit local CLI operation.
- Authorization approval requires explicit hostname allowlist rules.
- Scope snapshots bind a target and approved authorization into canonical JSON with a SHA-256 digest.
- Pre-dispatch validation checks digest integrity, authorization state, target consistency, expiry, and revocation.
- Administrators can revoke snapshots; snapshot creation and validation do not send traffic.
- Alembic migration for adding user and ownership data to existing local databases.
- Hostname allowlist check; no active network scanner.

## Trust boundaries and limitations
1. Authorization records are evidence placeholders and remain pending; they are not independent proof of permission.
2. Each project belongs to one authenticated user. There is no team sharing or admin role workflow yet.
3. Registration is public and currently lacks email verification and throttling.
4. JWT access tokens expire; refresh and server-side revocation are not implemented.
5. Scope snapshots bind hostname rules to approved authorization records, but do not yet pin DNS answers or validate redirect destinations.
6. Redirect destinations and resolved IPs must be checked before any future network access.
7. Worker egress must be restricted; model-generated strings must never be executed as shell commands.
8. Intrusive, destructive, or state-changing actions require human approval.
9. The API must remain private until rate limiting, operational monitoring, and additional hardening are complete.

## Not implemented
Multi-factor authentication, verified-email flow, password reset, role-based administration, refresh/revocation, PostgreSQL deployment, Redis queue, immutable scope snapshots, scanner, agents, worker isolation, and production deployment hardening.
