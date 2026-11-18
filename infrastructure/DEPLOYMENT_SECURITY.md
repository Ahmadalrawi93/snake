# Production deployment security boundary

The Compose backend is published only on host loopback:

`127.0.0.1:8000:8000`

A host-managed reverse proxy must terminate HTTPS and proxy requests to
`http://127.0.0.1:8000`. Do not change this to `8000:8000` on a public
host. If the reverse proxy runs as another Compose service, place it on the
same private Compose network and publish only the proxy's TLS ports.

## Required environment

Set these values in the deployment environment (do not commit secrets):

- `SNAKE_JWT_SECRET_KEY`: cryptographically random secret, at least 32 characters.
- `SNAKE_ALLOWED_ORIGINS`: comma-separated exact HTTPS origins, without paths,
  credentials, query strings, fragments, wildcards, or localhost.
- `SNAKE_ENVIRONMENT=production`.
- `SNAKE_SESSION_COOKIE_SECURE=true`.

The Compose file sets the environment name and secure-cookie flag explicitly
and refuses to start without a configured allowed-origin list and JWT secret.
The backend validates production CORS origins at startup. A localhost origin
or HTTP origin is acceptable only in local development, never in production.

## Reverse proxy requirements

- Redirect all HTTP traffic to HTTPS.
- Apply request-rate limits to `/api/v1/auth/login`,
  `/api/v1/auth/token`, and `/api/v1/auth/register`.
- Enforce request-body size limits and reasonable connection/time limits.
- Do not expose the backend's port publicly.
- Do not forward arbitrary client-supplied `X-Forwarded-For` or
  `X-Real-IP` values as trusted identity. Overwrite forwarding headers at
  the trusted proxy. The application currently uses the socket peer address
  for its account/source failed-login bucket and does not consume forwarded
  headers; behind a proxy, that means the proxy peer is the application-visible
  source. Edge rate limiting is therefore mandatory.
- Keep proxy and application logs free of Authorization headers, cookies,
  passwords, CSRF values, and reset tokens.

This repository does not currently ship a TLS reverse-proxy configuration.
The Compose binding is a defensive default, not a complete internet-facing
deployment. Configure and review the proxy separately before exposing the
service.
