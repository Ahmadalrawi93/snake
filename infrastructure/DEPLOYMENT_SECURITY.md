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
- `SNAKE_ALLOWED_HOSTS`: comma-separated exact API hostnames (for example `api.example.com`), without schemes, paths, wildcards, or localhost.
- `SNAKE_MAX_REQUEST_BODY_BYTES`: API request-body cap; defaults to 2 MiB and is constrained to 1 KiB–10 MiB.
- `SNAKE_ALLOWED_ORIGINS`: comma-separated exact HTTPS origins, without paths,
  credentials, query strings, fragments, wildcards, or localhost.
- `SNAKE_ENVIRONMENT=production`.
- `SNAKE_SESSION_COOKIE_SECURE=true`.

The Compose file sets the environment name and secure-cookie flag explicitly
and refuses to start without a configured allowed-origin list and JWT secret.
The backend validates production CORS origins and Host allowlists at startup. Requests with unlisted Host headers are rejected. Production API docs and the OpenAPI schema endpoints are disabled. API responses receive restrictive security headers; HSTS is emitted only in production. Request bodies are capped at the ASGI layer, including streamed bodies without Content-Length. Evidence artifacts retain their separate decoded 1 MiB limit. A localhost origin
or HTTP origin is acceptable only in local development, never in production.

## Reverse proxy requirements

- Redirect all HTTP traffic to HTTPS.
- Apply request-rate limits to `/api/v1/auth/login`,
  `/api/v1/auth/token`, and `/api/v1/auth/register`.
- Enforce edge request-rate limits and reasonable connection/time limits; the application also enforces its configured request-body cap.
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


## API request and response controls

The application uses an exact `SNAKE_ALLOWED_HOSTS` allowlist through
Starlette TrustedHostMiddleware. In production, configure the public API
hostname(s), not the frontend hostname unless both services share that host.
Wildcard hosts, schemes, paths, and localhost are rejected.

The default request-body cap is 2 MiB (configurable from 1 KiB to 10 MiB).
The cap is enforced while receiving ASGI body chunks, so requests without a
Content-Length header are still bounded. The evidence vault independently
limits decoded artifacts to 1 MiB. Production disables Swagger, ReDoc, and
the OpenAPI schema route. Responses receive restrictive CSP, frame, MIME,
referrer, and permissions headers; HSTS is enabled only in production, where
TLS termination at a trusted edge is mandatory.
