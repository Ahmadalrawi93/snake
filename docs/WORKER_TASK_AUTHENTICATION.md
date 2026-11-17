# Worker task authentication

`app.core.worker_signing` adds versioned HMAC-SHA256 signatures over a
canonical JSON representation of the strict `WorkerTaskEnvelope`.

- Signatures use the `v1=<hex digest>` format.
- A dedicated secret of at least 32 characters is required; do not reuse the
  user JWT secret.
- Verification uses constant-time comparison.
- Any envelope field modification invalidates the signature.

This is integrity/authenticity only. It does not provide replay prevention,
atomic job claiming, authorization, scope revalidation, or network isolation.
Those checks remain independent requirements. The current validator container
does not load a signing secret or accept signed work from a transport, and no
worker dispatch is enabled.
