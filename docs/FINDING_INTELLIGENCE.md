# Finding Intelligence & Deduplication

SNAKE compares finding candidates conservatively. The first version is deterministic and advisory only.

## Signals

- Exact category + hypothesis fingerprint: `exact_duplicate`.
- Same category and high normalized title-token Jaccard similarity (>= 0.80): `possible_duplicate`.
- Same category, title similarity >= 0.55, and at least two shared source observation IDs: `possible_duplicate`.
- Different categories are not grouped by this initial engine, even when titles or observations overlap.
- Shared observations alone never imply duplicate findings.

## Safety properties

- No automatic merge, suppression, deletion, or candidate status change.
- Every comparison requires human review.
- A possible duplicate is a review lead, not proof of the same root cause.
- Two findings affecting the same endpoint may have different authorization, state, tenant, or impact conditions. Similarity must not collapse them.
- Scores are lexical similarity, not calibrated probabilities or model confidence.

## Current limitations

The first version compares category, title, and source observation IDs. It does not yet compare root-cause evidence, HTTP method, parameter, principal/role, tenant boundary, object ownership, workflow state, or impact. Those structured dimensions should be added only when supported by validated evidence records.
