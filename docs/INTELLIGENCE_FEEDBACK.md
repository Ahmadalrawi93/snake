# Intelligence Feedback Profile

SNAKE now exposes a deterministic, read-only project feedback profile:

`GET /api/v1/projects/{project_id}/intelligence-feedback`

The endpoint is restricted to the authenticated project owner. It groups human evaluations by a SHA-256 fingerprint derived from the triage category and a normalized hypothesis string. Multiple reviewers of the same analysis run count as one sample; a confirmed review wins conflicting labels, and a false-positive label counts only when no reviewer confirmed that run. Numeric and UUID-like path identifiers are normalized to reduce trivial route-ID variations. Output ordering is deterministic.

## Label semantics

- `confirmed` and `false_positive` are resolved human outcomes and require an evidence digest at submission.
- `inconclusive` and `duplicate` are counted for workload/context only. They are not negative or positive labels.
- Analysis runs without a human evaluation are excluded completely.
- The profile is scoped to one owned project; it does not pool data across users or projects.

## Conservative recommendation

A pattern is marked `deprioritize` only when it has at least three human false-positive evaluations and no confirmed evaluation. This is a prioritization hint, not a blocklist: it does not suppress tests, alter AI prompts, confirm vulnerabilities, change severity, or authorize scanning. A confirmed example prevents deprioritization.

Patterns with fewer than three reviews or no resolved outcomes remain `insufficient_evidence`. Other resolved patterns are marked `retain`.

## Limitations

This is deterministic aggregation, not machine learning or autonomous self-improvement. Fingerprints are lexical and can merge distinct hypotheses that use similar wording or split equivalent hypotheses phrased differently. Human labels can themselves be mistaken. Evidence digests prove only that a digest was supplied, not that the evidence is independently trustworthy. The profile must be reviewed alongside the underlying evidence and program scope.

The profile is computed from append-only evaluation records on read; no mutable learned state or new database table is introduced. It never changes the required disposition `requires_independent_validation` and never enables execution.

## Optional AI-analysis integration

The DeepSeek adapter accepts an optional, caller-supplied `IntelligenceFeedbackProfile`. When provided, it is included as historical aggregate context in the model request. It is omitted entirely by default. The system instruction explicitly prohibits treating the profile as proof, suppressing reasonable hypotheses, or overriding current evidence. The adapter still validates the returned triage against the current observation IDs and enforces `requires_independent_validation`.

The adapter does not query the database or select a project profile itself. The authenticated application layer must obtain the profile through the owner-scoped API for the same project being analyzed. Do not reuse a profile across unrelated projects or targets. Current aggregation is project-wide, not target-, program-, or model-version-specific, so it is a weak prioritization signal and can be misleading in projects containing unrelated applications. A future iteration should stratify profiles by authorized target/program and model version before using them routinely.
