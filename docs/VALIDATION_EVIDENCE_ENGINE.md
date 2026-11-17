# Validation Evidence Engine

This engine evaluates **human-attested evidence records** against one existing manual validation strategy and the exact analysis-context digest.

## Evidence contract
Each evidence item records a bounded type, whether it supports, contradicts, or only contextualizes the hypothesis, a short statement, source label, timestamp, and source observation IDs. The `human_attested=true` field is an assertion supplied by the caller, not cryptographic proof of reviewer identity; a future authenticated review API must bind the record to the logged-in reviewer. The schema deliberately has no fields for request payloads, credentials, commands, arbitrary URLs, or state-changing actions.

## Deterministic gates
- Strategy ID and context digest must match.
- Every strategy/evidence observation reference must exist in the supplied analysis context.
- Written program policy, expected behavior, observed behavior, impact context, supporting observed behavior, and linkage to the strategy's original observations are required for human-review readiness.
- Contradictory evidence yields `mixed`, not a positive conclusion.
- Impact can only be labeled `documented_not_independently_verified`.

## Critical limitation
`human_review_ready` means the evidence bundle has the required recorded categories; it does **not** mean the hypothesis is true, impact is proven, or a vulnerability is confirmed. Every assessment retains `requires_independent_human_validation` and `execution_enabled=false`.

This is currently a pure internal function. No API endpoint, database persistence, scanner invocation, network request, or automatic finding creation is added.


## Evidence coverage (not confidence or severity)

The deterministic coverage assessor reports whether documentary elements are present:
written program policy, expected behavior, supporting observed behavior, an
authorized test-account record, impact context, and traceable source observation
references. It returns a 0–100 **coverage score** and a missing-elements list.

The score is not a probability, confidence estimate, CVSS score, exploitability
rating, or proof that a statement is true. A complete score only means that the
listed evidence categories were recorded. The assessment explicitly leaves
impact independently verified as false and has no field for vulnerability
severity. Contradictory evidence is counted and remains a blocker in the
existing qualification workflow.

The candidate orchestration result now includes this coverage assessment
alongside the existing validation evidence assessment and qualification. No
automated testing or finding confirmation is triggered.
