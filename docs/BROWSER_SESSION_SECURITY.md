# Browser Session Security

## Authentication paths

- Browser clients use `POST /api/v1/auth/login`. The response contains a CSRF token only; the access JWT is set in an HttpOnly cookie.
- Non-browser API clients use `POST /api/v1/auth/token` and receive a stateless bearer token.
- Cookie-authenticated state-changing requests require the CSRF cookie value in the configured header and an exact allowed Origin.

## Revocable browser sessions

Browser login creates a JWT with a unique `jti` and `token_use=browser_session`.
The database stores only SHA-256(`jti`) in `user_sessions`, together with
user ID, expiry, creation time, and optional revocation time. Every request
authenticated by a browser session checks that record and rejects missing,
expired, or revoked sessions. The raw JWT and raw `jti` are never stored.

- `POST /api/v1/auth/logout` revokes the current browser session before clearing cookies.
- `POST /api/v1/auth/logout-all` revokes all active browser sessions for the authenticated user.
- `GET /api/v1/auth/csrf` requires a valid browser session and returns the CSRF token with `Cache-Control: no-store`.

## Migration and operational boundaries

Apply Alembic revision `0023_revocable_user_sessions` before deploying this
backend to an existing database. Do not use `Base.metadata.create_all` as a
production migration mechanism.

Revocation applies to browser-session JWTs. Stateless bearer tokens issued by
`/api/v1/auth/token` are separate credentials and are not revoked by browser
logout endpoints. They need independent credential lifecycle controls.

For production, use HTTPS, a strong random `SNAKE_JWT_SECRET_KEY`,
`SNAKE_ENVIRONMENT=production`, and `SNAKE_SESSION_COOKIE_SECURE=true`.


## API bearer token lifecycle

`POST /api/v1/auth/token` issues a bearer JWT with a unique `jti` and
`token_use=api_access`. Only SHA-256(`jti`) is stored in
`api_access_tokens`; every authenticated bearer request checks that the
record is active and unexpired.

- `POST /api/v1/auth/api-tokens/revoke` revokes the bearer token used for the request.
- `POST /api/v1/auth/api-tokens/revoke-all` revokes every active API token for that user, including the token used for that request.

These endpoints require an API bearer token. Browser cookies cannot invoke
them as a substitute. Token revocation is enforced on the next request; it
does not retroactively terminate work already authorized and executing.

Apply Alembic revision `0024_revocable_api_tokens` after revision
`0023_revocable_user_sessions` before deploying this change.


## Credential cutover

JWTs without a registered `jti` and recognized `token_use` are rejected.
This intentionally invalidates stateless bearer tokens issued by older
versions of `/auth/token`; API clients must authenticate again to obtain a
registered token. This prevents an untracked legacy credential from bypassing
server-side revocation.


## Credential inventory

Authenticated users can list active browser sessions with `GET /api/v1/auth/sessions`
and revoke a specific owned session with
`POST /api/v1/auth/sessions/{session_record_id}/revoke`. They can list active
API tokens with `GET /api/v1/auth/api-tokens` and revoke a specific owned
record with `POST /api/v1/auth/api-tokens/{token_record_id}/revoke`.
Inventory responses expose only record IDs and timestamps; they never return
JWTs, raw token identifiers, or stored digests. Lists are limited to the
100 most recently created active records. Ownership is enforced in each
database query.


## Password changes

Authenticated users can change their password with
`POST /api/v1/auth/password/change`, supplying `current_password` and a
new password of at least 12 characters. The current password is verified
before any mutation. Reusing the current password is rejected.

A successful change updates the password hash and revokes every active
browser session and API bearer token for that user in the same database
transaction. The response clears browser cookies. The user must authenticate
again with the new password on each client.

This endpoint is a password-change flow for an already authenticated user;
it is not an email-based forgotten-password reset. A reset flow must not be
exposed until a verified email-delivery channel, single-use expiring reset
tokens, and abuse controls are implemented.
