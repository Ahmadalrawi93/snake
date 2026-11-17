# SNAKE Architecture

## Intended system
- Next.js dashboard for projects, targets, jobs, findings, reports, and audit history.
- FastAPI control plane for identity, authorization, scope, job lifecycle, and policy.
- LangGraph (candidate) orchestration for supervised specialist agents.
- PostgreSQL for durable records; pgvector for reviewed knowledge retrieval.
- Redis for queueing and coordination.
- Isolated workers for scanner adapters; local Kali worker and optional cloud worker.
- Model router selects providers by task, quality, latency, and budget.

## Trust boundaries
1. Authorization is an explicit record, never inferred by an LLM.
2. Scope policy is deterministic and enforced by API and worker.
3. Redirect destinations and resolved IPs must be checked before network access.
4. Worker egress is restricted; model-generated strings are never executed as shell commands.
5. Intrusive, destructive, or state-changing actions require human approval.
6. Evidence and decisions are audited.
7. Secrets stay outside prompts and source control.

## Current implementation
Only the FastAPI foundation, hostname allowlist policy, tests, and dashboard shell exist. Database, authentication, scanner, agents, queue, and worker isolation are not implemented.
