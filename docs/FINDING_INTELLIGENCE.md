# Finding Intelligence & Deduplication

SNAKE compares persisted unconfirmed candidates using deterministic, advisory signals.

## Signals

- Exact category + hypothesis fingerprint: `exact_duplicate`.
- Same category with high normalized title-token similarity (>= 0.80): possible duplicate.
- Same category with high evidence-token similarity (>= 0.72): possible duplicate.
- Same category with moderately similar title plus shared observations, or matching evidence plus a shared normalized route: possible duplicate.
- Different categories may be compared only when they belong to a configured broad root-cause family. Cross-category candidates require both strong evidence-text overlap (>= 0.72) and at least one shared normalized route.
- Numeric and UUID-like route identifiers are normalized to `:id` before route comparison.
- Shared observation IDs alone never imply duplicate findings.

## Interpretation

Evidence-token similarity is lexical overlap, not semantic understanding. Route overlap is a supporting clue, not proof that the same code path or authorization control is involved. A shared route may host independent bugs, such as an object ownership failure and a workflow-state bypass.

## Safety properties

- No automatic merge, suppression, deletion, or candidate status change.
- Every comparison requires human review.
- A possible duplicate is a review lead, not proof of the same root cause.
- Distinct categories outside the configured families are never grouped by this version.
- Scores are not calibrated probabilities, severity, or model confidence.

## Current limitations

The engine does not compare HTTP method as a structured field, parameter names, principal/role, tenant boundary, object ownership, workflow state, or independently verified impact. It does not perform network requests or call an LLM. It must not suppress a candidate based on similarity.
