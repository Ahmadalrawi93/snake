# Persisted Finding Candidates

## API

- `POST /api/v1/analysis-runs/{analysis_run_id}/finding-candidates`
- `GET /api/v1/analysis-runs/{analysis_run_id}/finding-candidates`

Both endpoints are authenticated and project-owner scoped.

## Stored record

A record stores the candidate fingerprint, qualification JSON, exact validation evidence bundle JSON, SHA-256 of canonicalized evidence bundle JSON, analysis run, project, creator, and creation timestamp. A unique constraint prevents multiple candidate records with the same fingerprint in one analysis run. SQLite and PostgreSQL triggers reject updates and deletes.

Only `human_review_candidate` artifacts can be persisted. The database enforces `finding_status=unconfirmed` and `execution_enabled=false`.

The API checks that:
- the analysis run belongs to the authenticated project owner;
- the evidence bundle context digest equals the analysis run context digest;
- evidence and observation IDs in the qualification exactly match the supplied bundle;
- the candidate remains unconfirmed and non-executable.

Human finding decisions now require a persisted candidate with matching analysis run, project, and fingerprint. A caller cannot submit an arbitrary fingerprint to the decision endpoint.

## Trust boundary

The API structurally binds the submitted artifact to its run and evidence bundle. It does not independently recompute the original qualification from raw observations or establish that statements in the evidence bundle are true. Candidate creation must be performed by trusted server-side orchestration after the deterministic qualification engine runs. A human decision remains an authenticated reviewer assertion, not cryptographic proof or automatic authorization to test.
