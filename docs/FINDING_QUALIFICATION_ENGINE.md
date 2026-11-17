# Finding Qualification Engine

The Finding Qualification Engine converts an existing validation strategy and its human-recorded evidence assessment into a conservative **candidate**, not a confirmed vulnerability.

## Decision rules

A candidate can reach `human_review_candidate` only when:
- the strategy ID matches both the evidence bundle and assessment;
- the evidence assessment is `human_review_ready`;
- evidence is marked consistent and has no contradictions;
- expected behavior, supporting observed behavior, program policy, and impact context have been documented by the upstream evidence assessment;
- impact is still labelled `documented_not_independently_verified`.

Missing, mixed, contradictory, or incomplete evidence remains `insufficient_evidence`. A repeated category + normalized hypothesis fingerprint is marked as a duplicate candidate and is not promoted again.

## Hard limits

- Every output has `finding_status=unconfirmed`.
- The engine never emits a confirmed status, severity, CVSS score, exploit payload, command, or test request.
- A candidate fingerprint is a deterministic deduplication hint, not proof that two issues are identical.
- Impact context is documentation, not independent verification.
- Human attestation in the upstream bundle is caller-supplied and is not cryptographic reviewer identity.
- The prior-fingerprint list is supplied by the caller; durable cross-run deduplication and ownership enforcement are not implemented here.
- This pure function performs no database writes, network requests, or active testing.
- A separate authenticated human decision workflow is still required before any report can be labelled confirmed.

The output is triage metadata only. It does not establish authorization and cannot enable scan execution.
