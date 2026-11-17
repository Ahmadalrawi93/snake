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
- The API binds the decision to an owned analysis run and a caller-supplied candidate fingerprint. It does **not yet** prove that this fingerprint corresponds to a server-persisted Finding Qualification artifact; candidate qualification artifacts are not yet persisted as first-class records.
- A `confirmed` decision is therefore a human-recorded review outcome, not an automated platform assertion that the vulnerability is objectively true.
- Multi-reviewer quorum, independent reviewer separation, evidence file storage, and signed evidence attestations are not implemented.
- The workflow does not authorize testing, alter scope, or enable execution.

Next hardening step: persist qualification artifacts server-side, bind their exact evidence bundle digest, and accept decisions only for those persisted candidate records.
