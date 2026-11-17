# Analysis and Candidate Orchestrator

## Purpose

The orchestrator connects analysis, strategy generation, human evidence assessment, qualification, and candidate persistence. It is a synchronous application service, not a scanner or background worker.

## Analysis stage

`execute_analysis_pipeline`:
1. verifies project ownership and target/project association before contacting the provider;
2. explicitly invokes the DeepSeek adapter;
3. validates the response and builds a deterministic manual-only validation strategy;
4. persists the immutable analysis run, context/correlation digests, strategy, and provider usage metadata.

The function does not commit. The caller owns commit/rollback. It is not invoked by app startup, scan-job creation, or worker dispatch. API keys must be supplied by trusted server-side code, never by an untrusted client.

## Candidate stage

`qualify_and_persist_candidate`:
1. loads the analysis run through an owner-scoped query;
2. recomputes the canonical context digest and requires an exact match;
3. loads the strategy from the persisted analysis result;
4. recomputes the evidence assessment;
5. recomputes candidate fingerprint and qualification;
6. persists only a non-duplicate `human_review_candidate`.

Client-supplied assessment and qualification summaries are not accepted. Incomplete or duplicate hypotheses are returned as non-persisted qualifications. The caller controls transaction commit/rollback.

## Limitations

- Raw observation content is not stored in the analysis-run table. The caller must supply the context again; the digest prevents substitution but does not independently prove that observations originated from the worker. A server-owned immutable observation snapshot is a required next stage.
- Evidence statements and reviewer attestations remain human-submitted data. Completeness checks do not prove factual truth.
- No HTTP route, queue, scheduler, scanner, worker execution, or automated validation is added.
- AI output remains unconfirmed and cannot authorize testing.
