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

These are cryptographic primitives, not a transport. They do not provide replay
prevention, job authorization, scope revalidation, worker identity provisioning,
or network isolation. The current validator container does not load a signing
secret, exchange signed messages, or connect to the database receipt ledger.
No worker dispatch or scan execution is enabled.
