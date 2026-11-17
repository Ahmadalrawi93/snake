# Agent Layer — Contract Only

The future orchestrator is planned around a supervisor and specialist workers:
- Recon Agent: passive and explicitly scoped asset discovery.
- Analysis Agent: correlate observations and form test hypotheses.
- Validation Agent: execute only policy-approved, non-destructive checks by default.
- Reporting Agent: produce evidence-backed findings.
- Memory Agent: retrieve and propose reusable methodology updates.

## Non-negotiable boundary
Agents do not grant themselves permission. Every proposed action must pass deterministic backend policy. The model must never be the source of truth for scope, authorization, rate limits, or approval state.

No agent runtime is implemented in Phase 1.
