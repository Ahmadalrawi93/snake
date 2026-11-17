# Business Logic Intelligence

SNAKE now derives conservative business-logic review leads from URL observations already present in the target-scoped analysis context.

## What it extracts

- Known resource path families such as users, accounts, orders, invoices, payments, roles, documents, and projects.
- Collection routes and identifier-shaped object routes (numeric/UUID-like identifiers normalized to `:id`).
- Explicit action-like path terms such as approve, cancel, delete, export, transfer, and pay.
- Evidence-linked hypotheses for object-level authorization and potentially sensitive actions, with validation questions.

## Hard limits

- No HTTP requests, crawling, endpoint guessing, DNS, or active testing.
- No HTTP method inference, role inference, workflow sequencing, object ownership inference, or state-transition proof.
- A path containing `approve` does not prove an approval operation exists. A path containing `:id` does not prove IDOR.
- Every candidate retains source observation IDs and requires independent human validation.
- This is a deterministic lead generator, not a business-logic vulnerability detector.

## Safe validation direction

When an authorized program permits manual testing, use dedicated test accounts and test-owned objects. Compare access and state changes across roles and ownership boundaries. Do not test destructive actions against real users or production data.
