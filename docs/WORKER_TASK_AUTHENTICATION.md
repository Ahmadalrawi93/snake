# Worker task and acknowledgement authentication

`app.core.worker_signing` provides HMAC-SHA256 signatures for strict task envelopes
and validation-only worker acknowledgements.

- Task signatures cover canonical JSON for `WorkerTaskEnvelope`.
- Acknowledgement signatures cover canonical JSON for `WorkerValidationResult`
  with a result-specific domain-separation prefix.
- Signatures use the `v1=<hex digest>` format.
- A dedicated secret of at least 32 characters is required; never reuse the
  user JWT secret.
- Verification uses constant-time comparison.
- Any signed payload field modification invalidates its signature.

The result contract is deliberately limited to `accepted` or `rejected`, includes
the task ID and envelope digest, and fixes `execution_enabled=false`. It cannot
claim that a scan completed or provide scan findings.

These signatures are now used by the isolated stdin/stdout validator prototype.
That prototype verifies signed task metadata and emits a signed validation-only
acknowledgement. It is not a network transport and is not connected to the backend
receipt ledger. The signatures do not provide replay prevention, job authorization,
scope revalidation, worker identity provisioning, or network isolation. No scan
execution is enabled.
