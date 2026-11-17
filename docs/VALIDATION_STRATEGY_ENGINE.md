# Validation Strategy Engine

The strategy engine converts a validated AI triage hypothesis and deterministic route evidence into a prioritized **manual review plan**.

## Inputs and trust boundaries
- Analysis context containing previously collected observations.
- Strict AI triage output whose observation references are checked against the context.
- Deterministic business-logic and cross-surface profiles derived from the same context.

Every evidence ID is rechecked against the context. Evidence outside that context is rejected. Route-derived object authorization leads require paired collection and identifier-shaped routes. Same-host co-occurrence remains context, not proof.

## Output
Each strategy item contains a bounded priority, explicit priority basis, hypothesis, source observation IDs, missing evidence, validation questions, manual review actions, and prerequisites. Priority is a review-order hint, **not severity, exploitability, or a confirmed finding**.

## Safety
The output is manual-human-review-only. It contains no URLs, HTTP methods, payloads, shell commands, credentials, request templates, or state-changing instructions. It performs no network, DNS, scanner, or model calls. A plan does not grant authorization. Before any testing, the backend must verify the current approved authorization and immutable scope snapshot, and a human must approve the specific activity. Irreversible actions and real user data are excluded.

The module is an internal pure function; no API endpoint or automatic execution path is added.
