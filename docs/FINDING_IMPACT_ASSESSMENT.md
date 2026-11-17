# Finding Impact & Severity Assessment

SNAKE's impact assessment is deterministic and evidence-bound. It does not ask an LLM to invent impact, infer confidentiality or privilege impact from a title, or convert a potential scenario into a demonstrated one.

## Inputs

A structured `FindingImpactClaim` is a human-attested annotation tied to:
- an existing evidence item of type `impact_context` with relationship `supports`;
- one or more observation IDs already referenced by that exact evidence item;
- an explicit impact dimension, level, verification state, affected scope, and data sensitivity.

Free-text statements are not parsed to infer dimensions, scope, sensitivity, or severity.

## Output

The engine reports demonstrated and potential dimensions separately. A severity suggestion is produced only when the evidence assessment is consistent, no blockers remain, and the claim is observed with known scope and sensitivity. Potential claims never contribute to severity. Unknown scope or sensitivity blocks a suggestion.

The severity suggestion is a triage aid, not a final rating. `final_severity` remains `not_assessed`; CVSS is never generated. Every result requires independent human validation. The engine does not confirm a vulnerability, authorize testing, or execute requests.

## Authenticated persistence API

Impact assessments are submitted against an existing persisted candidate. The API does not accept a client-supplied assessment result or severity. It reloads the candidate's immutable qualification and evidence bundle, verifies their digest, rebuilds the analysis context from signed worker-observation provenance, re-evaluates the evidence, and then runs the deterministic impact engine.

- `POST /api/v1/finding-candidates/{candidate_id}/impact-assessments`
  - Requires a bearer-authenticated project owner.
  - Body: `{"claims": [...]}`, where every claim must be explicitly human-attested.
  - Repeated identical submissions are idempotent.
  - Distinct assessments append new immutable records.
- `GET /api/v1/finding-candidates/{candidate_id}/impact-assessments`
  - Returns the candidate's append-only assessment history to its project owner.

Each record binds the candidate, analysis run, project, reviewer, evidence-bundle digest, claims digest, and assessment digest. Audit events are recorded. Database triggers reject update and delete operations. The stored final severity remains `not_assessed`, CVSS remains null, and execution remains disabled.

## Operational status

The API and migration are implemented in revision `0022_finding_impact_assessments`. Apply the migration only after pulling the change and testing it against a separate disposable database. Do not point migration tests at an existing production or personal database.
