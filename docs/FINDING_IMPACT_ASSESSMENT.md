# Finding Impact & Severity Assessment

SNAKE's impact assessment is deterministic and evidence-bound. It does not ask an LLM to invent impact, infer confidentiality or privilege impact from a title, or convert a potential scenario into a demonstrated one.

## Inputs

A structured `FindingImpactClaim` is a human-attested annotation tied to:
- an existing evidence item of type `impact_context` with relationship `supports`;
- one or more observation IDs already referenced by that exact evidence item;
- an explicit impact dimension, level, verification state, affected scope, and data sensitivity.

Free-text statements are not parsed to infer dimensions, scope, sensitivity, or severity.

## Output

The engine reports demonstrated and potential dimensions separately. A severity suggestion is produced only for observed claims with known scope and sensitivity and a consistent evidence assessment. Potential claims never contribute to severity. Unknown scope or sensitivity blocks a suggestion for that claim.

The severity suggestion is a triage aid, not a final rating. `final_severity` remains `not_assessed`; CVSS is never generated. Every result requires independent human validation. The engine does not confirm a vulnerability, authorize testing, or execute requests.

## Current integration boundary

The pure assessment engine is exposed through the candidate-analysis orchestration result. Until a dedicated authenticated API and persistence workflow is added, structured impact claims are supplied by the trusted orchestration caller; they are not accepted as a standalone unauthenticated endpoint or silently persisted.
