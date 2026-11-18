# Browser Session Security

## Authentication paths

- Browser clients use `POST /api/v1/auth/login`. The response contains a CSRF token only; the access JWT is set in an HttpOnly cookie.
- Non-browser API clients use `POST /api/v1/auth/token` and receive a revocable bearer token registered server-side.
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

Apply Alembic revisions `0023_revocable_user_sessions`,
`0024_revocable_api_tokens`, and `0025_auth_failed_attempt_buckets` in order
before deploying this backend to an existing database. Do not use
`Base.metadata.create_all` as a production migration mechanism.

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
`0023_revocable_user_sessions`, then apply `0025_auth_failed_attempt_buckets`
for persistent failed-password throttling.


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
Inventory responses expose only record IDs, timestamps, and a boolean marker
for the current browser session; they never return JWTs, raw token identifiers,
or stored digests. Lists are limited to the 100 most recently created active
records. Ownership is enforced in each database query.


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


## Audit trail

Credential lifecycle operations write append-only audit events without storing
passwords, raw JWTs, CSRF values, or token digests. Events cover password
changes, current/all-session revocation, and individual/all-API-token
revocation. Bulk events include only the number of records revoked.


## Failed password-attempt throttling

Browser password login and non-browser API-token issuance share a persistent
failed-attempt bucket scoped to the normalized account email and the server-observed
client address. Eight failed password checks within a
15-minute window trigger a 15-minute temporary block. The same generic
credential error is returned for unknown email addresses and incorrect
passwords; an active block returns HTTP 429 with a `Retry-After` header.
A successful password authentication clears the matching account-and-source failure bucket.

The bucket key is an HMAC digest derived from the normalized email, the
server-observed client address, and the server secret. Raw email addresses,
client addresses, and passwords are not stored in the throttling table. Updates
use database-native atomic upserts for SQLite and PostgreSQL, so counters are
not dependent on a single application process.
Old buckets are opportunistically pruned after seven days.

This per-account/per-source control is not a substitute for edge/WAF controls,
credential-stuffing detection, or trusted-proxy IP throttling. Deployments
should add network-level rate limits at their reverse proxy and must not trust
client-supplied forwarding headers unless they are overwritten by a trusted
proxy.


## Production origin and network boundary

Production startup rejects wildcard, HTTP, localhost, path-bearing, credential-
bearing, query-bearing, fragment-bearing, and malformed CORS origins. Configure
only exact HTTPS frontend origins. The Compose deployment sets
`SNAKE_ENVIRONMENT=production` (the setting name consumed by the backend),
requires `SNAKE_ALLOWED_ORIGINS`, and enables secure session cookies.

Compose binds the API to host loopback at `127.0.0.1:8000`; it is not intended
to be exposed directly to the public internet. A separately configured HTTPS
reverse proxy must terminate TLS and proxy to that loopback address. The
repository does not yet include a TLS proxy configuration. See
[deployment security](../infrastructure/DEPLOYMENT_SECURITY.md) for required
proxy controls and limitations.


## JWT signing-key rotation

New browser-session and API bearer JWTs are always signed with the active
`SNAKE_JWT_SECRET_KEY`. During a planned rotation, the backend can temporarily
verify tokens signed by up to five previous keys configured through the
comma-separated `SNAKE_JWT_PREVIOUS_SECRET_KEYS` setting. Previous keys are
verification-only; they are never used to sign new tokens. Production requires
each previous key to be at least 32 characters, rejects duplicates, and
rejects repeating the active key.

Use a staged deployment:

1. Generate a new cryptographically random secret (at least 32 characters).
2. Deploy the new secret as `SNAKE_JWT_SECRET_KEY` and the old secret as the
   only entry in `SNAKE_JWT_PREVIOUS_SECRET_KEYS`.
3. Confirm all application instances use the same active and previous key
   configuration before sending traffic.
4. Wait at least the maximum configured access-token lifetime, plus clock-skew
   and deployment overlap, so all tokens signed by the old key have expired.
5. Remove the old key from `SNAKE_JWT_PREVIOUS_SECRET_KEYS` and redeploy.

If an active key is suspected compromised, do not retain it as a previous key:
remove it from all verification key rings and revoke affected credentials.
This intentionally invalidates outstanding tokens. Coordinate key configuration
across all instances; inconsistent rings can cause intermittent authentication
failures. Keep secrets in the deployment secret manager, never in Git.
