# Finding Impact & Severity Assessment

SNAKE's impact assessment is deterministic and evidence-bound. It does not ask
an LLM to invent impact, infer confidentiality or privilege impact from a title,
or convert a potential scenario into a demonstrated one.

## Inputs and evidence binding

A structured `FindingImpactClaim` is a human-attested annotation tied to:
- an existing evidence item of type `impact_context` with relationship `supports`;
- one or more observation IDs already referenced by that exact evidence item;
- an explicit impact dimension, level, verification state, affected scope, and
  data sensitivity.

Free-text statements are not parsed to infer dimensions, scope, sensitivity,
or severity. Duplicate claims for the same evidence item and dimension are
rejected.

## Output and decision boundary

The engine reports demonstrated and potential dimensions separately. A
severity suggestion is produced only when the evidence assessment is
consistent, no blockers remain, and the claim is observed with known scope and
sensitivity. Potential claims never contribute to severity. Unknown scope or
sensitivity blocks a suggestion.

The severity suggestion is a triage aid, not a final rating.
`final_severity` remains `not_assessed`; CVSS is never generated. Every result
requires independent human validation. The engine does not confirm a
vulnerability, authorize testing, or execute requests.

## Authenticated persistence API

Impact assessments are submitted against an existing persisted candidate. The
API does not accept a client-supplied assessment result or severity. It reloads
the candidate's immutable qualification and evidence bundle, verifies their
digest and qualification binding, rebuilds the analysis context from verified
run provenance, re-evaluates the evidence, and then runs the deterministic
impact engine.

- `POST /api/v1/finding-candidates/{candidate_id}/impact-assessments`
  - Requires an authenticated user who owns the candidate's project.
  - Body: `{"claims": [...]}`, with 1–100 claims; empty submissions are rejected.
  - Each claim must be explicitly human-attested.
  - Repeated identical submissions are idempotent.
  - Distinct assessments append new immutable records.
- `GET /api/v1/finding-candidates/{candidate_id}/impact-assessments`
  - Returns the candidate's append-only assessment history to its project owner.
  - A candidate outside the caller's ownership boundary is reported as not found.

Each record binds the candidate, analysis run, project, reviewer,
evidence-bundle digest, claims digest, and assessment digest. On every read,
SNAKE validates the stored assessment schema and recomputes both the assessment
and claims digests before returning it. Integrity failures are rejected rather
than silently served. Audit events are recorded.

## Database invariants

Migration `0022_finding_impact_assessments` creates database-level mutation
guards for SQLite and PostgreSQL. Updates and deletes are rejected by triggers.
Database constraints also enforce:

- `final_severity = not_assessed`
- `cvss_vector IS NULL`
- `execution_enabled = false`

The SQLite trigger installer is shared by the migration and unit-test fixture;
a migration integration test exercises both upgrade and downgrade.

## Trust boundaries and limitations

- Human attestation is recorded as an assertion; SNAKE does not independently
  reproduce or prove the claimed impact.
- A severity suggestion is not a CVSS score and must not be copied as a final
  rating without independent validation.
- The API does not run HTTP requests, payloads, commands, or vulnerability
  tests.
- Database triggers protect against ordinary SQL update/delete operations.
  Database administrators able to alter schema or drop triggers remain
  outside this application-level immutability boundary.
- SQLite and PostgreSQL are the only supported dialects for this migration.

Apply the migration only after testing it against a separate disposable
database. Do not point migration tests at an existing personal or production
database.
