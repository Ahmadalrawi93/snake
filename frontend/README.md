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
- Report drafts can be generated on demand from the persisted candidate evidence after server-side provenance, integrity, and evidence-readiness checks. Drafts are not submitted or stored as final reports; the dashboard can copy the Markdown or download it as a `.md` file for human editing.
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

## Account security

Authenticated users can change their password from the Account Security panel.
The current password is verified, the new password must contain at least 12
characters, and the backend revokes all active browser sessions and API tokens
when the password is changed. The dashboard clears its local workspace and
requires a fresh sign-in. The same panel lists active browser sessions and API
token records and allows an owner to revoke an individual record. The current
browser session is identified so revoking it clears the local workspace.
Forgotten-password recovery is not exposed until verified email delivery and
single-use reset tokens are implemented.

## Session and CSRF security

The dashboard authenticates with a server-set HttpOnly session cookie; it does
not persist bearer tokens in local or session storage. The backend also sets a
separate CSRF cookie. The dashboard obtains its value through a no-store
session bootstrap endpoint and keeps it in memory; it sends that value in the
configured CSRF header for state-changing requests. The backend checks the
header/cookie match and requires an exact allowed Origin. This works when the
frontend cannot directly read cookies scoped to a separate API host.

For production, configure a strong random `SNAKE_JWT_SECRET_KEY`, set
`SNAKE_ENVIRONMENT=production`, and set `SNAKE_SESSION_COOKIE_SECURE=true`.
Use HTTPS. The backend refuses production startup when secure session cookies
are disabled. Keep `SNAKE_SESSION_COOKIE_SAMESITE=lax` when the frontend and API
are same-site; a genuinely cross-site deployment needs `none` plus Secure and
a carefully reviewed origin/CSRF configuration.

Bearer authentication remains supported for non-browser API clients through
the separate `POST /api/v1/auth/token` endpoint. API bearer tokens are
registered server-side and checked on every request. API clients can revoke
the current token with `POST /api/v1/auth/api-tokens/revoke`, or all their
active API tokens with `POST /api/v1/auth/api-tokens/revoke-all`; both
endpoints require the bearer token being revoked. Browser `POST /login` never
returns the access token in JSON; it returns only the in-memory CSRF value while
the HttpOnly session cookie carries authentication.

Browser sessions can be revoked with `POST /api/v1/auth/logout` or all at
once with `POST /api/v1/auth/logout-all`. The API token and browser session
registries are separate. Tokens issued before the server-side registry cutover
are rejected; API clients must authenticate again to obtain a registered token.

- Project-scoped candidate similarity is shown as a human-review aid. Possible duplicates can be linked through the append-only lifecycle only after a reviewer records a matching `duplicate` decision; no automatic merge occurs.
