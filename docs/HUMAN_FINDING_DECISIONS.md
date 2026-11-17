# Human Finding Decision Workflow

This workflow stores an authenticated reviewer's decision against an analysis run and a candidate fingerprint.

## API

- `POST /api/v1/analysis-runs/{analysis_run_id}/finding-decisions`
- `GET /api/v1/analysis-runs/{analysis_run_id}/finding-decisions?candidate_fingerprint={sha256}`

The access token supplies the evaluator identity. The API verifies that the analysis run belongs to a project owned by that user. Each reviewer can submit one decision for a given analysis run + candidate fingerprint. Decisions and their audit events are committed atomically. Decisions are append-only and database-enforced against update/delete.

## Decisions

- `confirmed`: requires an evidence SHA-256 and an explicit reviewer attestation.
- `false_positive`: requires an evidence SHA-256 and an explicit reviewer attestation.
- `inconclusive` and `duplicate`: no evidence digest is accepted.
- Notes are redacted before persistence.

## Important limitations

- The attestation is an explicit statement by the authenticated account holder, not cryptographic proof that the reviewer actually reproduced the issue.
- The API now requires a server-persisted candidate record for the same owned analysis run and fingerprint. The candidate record stores the exact evidence bundle and its SHA-256 digest, and is immutable.
- A `confirmed` decision is therefore a human-recorded review outcome, not an automated platform assertion that the vulnerability is objectively true.
- Multi-reviewer quorum, independent reviewer separation, evidence file storage, and signed evidence attestations are not implemented.
- The workflow does not authorize testing, alter scope, or enable execution.

Important: the candidate persistence endpoint structurally binds the submitted qualification and evidence bundle to the analysis run context digest and evidence IDs, but does not independently recompute the qualification from original observations. Candidate creation should therefore be called by the trusted analysis orchestration layer, not treated as proof that the evidence is true.
