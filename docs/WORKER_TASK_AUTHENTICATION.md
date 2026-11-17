# Worker task and acknowledgement authentication

The worker signing module provides HMAC-SHA256 signatures for strict task envelopes
and validation-only worker acknowledgements.

- Task signatures cover canonical JSON containing the envelope, intended worker ID,
  and key ID; changing any of them invalidates the signature.
- Acknowledgement signatures cover canonical JSON containing the result and key ID,
  using a result-specific domain-separation prefix.
- Signatures use the v1 hex-digest format and constant-time comparison.
- Every worker must have its own independent high-entropy secret (minimum 32
  characters). Never reuse the JWT secret or another worker's secret.
- key_id is a non-secret key version/selector. It is not itself proof of identity;
  the HMAC under that worker's unique secret provides message authentication.
- Worker validation rejects issue timestamps more than 30 seconds in the future,
  expired tasks, and task lifetimes longer than 300 seconds.

The result contract is limited to accepted or rejected, includes the task ID
and envelope digest, and fixes execution_enabled=false. It cannot claim that a
scan completed or provide scan findings.

The isolated stdin/stdout validator requires SNAKE_WORKER_ID, SNAKE_WORKER_KEY_ID,
and that worker's unique SNAKE_WORKER_SIGNING_SECRET. It rejects tasks addressed
to a different worker or key version. The backend acknowledgement verifier also
requires the expected worker ID and key ID and verifies using the selected worker
secret before consuming the matching durable receipt.

Secrets are currently injected out of band through environment variables by the
operator. There is no backend key registry, encrypted secret store, KMS integration,
automated provisioning, or key-rotation workflow yet. The caller of the internal
issuance/acknowledgement functions must select the correct secret from a trusted
configuration source. Do not place secrets in the database, source control, task
payloads, or logs.

There is still no HTTP/network transport or process orchestration connecting the
backend to the validator. Signatures do not independently provide authorization,
scope revalidation, replay protection across the process boundary, or network
isolation. No scan execution is enabled.
