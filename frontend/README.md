# SNAKE Frontend

## Local development

1. Start the FastAPI backend on `http://localhost:8000`.
2. From this directory, install dependencies and start Next.js:

```bash
npm install
npm run dev
```

3. Open `http://localhost:3000`.

Set `NEXT_PUBLIC_API_URL` when the backend is hosted at a different origin,
for example:

```bash
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
```

The backend must allow the frontend origin through `SNAKE_ALLOWED_ORIGINS`.
The default backend setting allows `http://localhost:3000`.

## Connected functionality

- Account registration, login, and current-user validation use the authenticated
  FastAPI endpoints.
- Project creation and owner-scoped listing are connected.
- Project workspace loads its registered targets, authorization references, immutable scope snapshots, and persisted AI analysis history.
- Analysis runs expose persisted finding candidates with integrity-checked qualification and evidence details.
- Candidate review supports encrypted evidence upload, append-only human decisions, evidence-bound impact annotations, and guarded lifecycle transitions. Confirming a finding requires a matching human decision and an evidence artifact stored in the encrypted vault.
- Impact annotations never set final severity or CVSS; final severity remains `not_assessed` and independent validation is required.
- Report drafts can be generated on demand from the persisted candidate evidence after server-side provenance, integrity, and evidence-readiness checks. Drafts are not submitted or stored as final reports; the dashboard can copy the Markdown for human editing.
- URL/domain targets can request a scope snapshot; the backend requires a currently valid, administrator-approved authorization whose hostname rules cover the target. Snapshot validation checks that the authorization, target, scope rules, expiry, and digest remain valid.
- Users with the administrator role can review pending authorization references and must enter explicit hostname rules and review notes before approval. Public registration never grants administrator privileges.
- Target registration stores a value only. It does not resolve DNS, send HTTP
  requests, or start a scan.
- Authorization references are always created with pending status. Recording a
  reference is not proof of permission and does not authorize testing.

AI analysis, scan dispatch, finding review, and reports are not represented as
working dashboard actions until their workflows are explicitly connected. A
scope snapshot is an authorization boundary record, not a scan command; its
execution flag remains disabled.

## Security note

The current local dashboard stores its short-lived bearer access token in
browser local storage. This is acceptable only as a development-stage
implementation; it is accessible to same-origin JavaScript and must be replaced
with a server-managed HttpOnly, Secure, SameSite cookie session before a
production deployment. Use HTTPS and a strong backend JWT secret outside local
development.

- Project-scoped candidate similarity is shown as a human-review aid. Possible duplicates can be linked through the append-only lifecycle only after a reviewer records a matching `duplicate` decision; no automatic merge occurs.
