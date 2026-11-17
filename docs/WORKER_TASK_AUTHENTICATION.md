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
acknowledgement. Backend-only functions now issue signed tasks after scope revalidation
and atomically reserve a job, then verify and bind acknowledgements to the matching
unconsumed receipt. These functions are not connected to the validator process by a
network transport or HTTP route. A shared HMAC secret does not provide distinct worker
identity. Signatures do not independently provide authorization, scope revalidation,
or network isolation. No scan execution is enabled.
