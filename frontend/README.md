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
- Project workspace loads its registered targets and authorization references.
- Target registration stores a value only. It does not resolve DNS, send HTTP
  requests, or start a scan.
- Authorization references are always created with pending status. Recording a
  reference is not proof of permission and does not authorize testing.

AI analysis, scan dispatch, finding review, and reports are not represented as
working dashboard actions until their workflows are explicitly connected.

## Security note

The current local dashboard stores its short-lived bearer access token in
browser local storage. This is acceptable only as a development-stage
implementation; it is accessible to same-origin JavaScript and must be replaced
with a server-managed HttpOnly, Secure, SameSite cookie session before a
production deployment. Use HTTPS and a strong backend JWT secret outside local
development.
