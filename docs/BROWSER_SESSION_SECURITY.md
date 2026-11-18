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
