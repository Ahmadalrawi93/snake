# Worker task and acknowledgement authentication

SNAKE now uses Ed25519 asymmetric signatures rather than a shared HMAC secret.

- The backend signs canonical task payloads with its Ed25519 private key.
- Each worker receives only the backend public key, so a compromised worker
  cannot mint backend-authorized tasks.
- Each worker signs its validation acknowledgements with its own Ed25519
  private key. The backend verifies using that worker's registered/configured
  public key; the backend does not need the worker private key.
- Task signatures bind the envelope, intended worker ID, and key ID.
  Acknowledgement signatures bind the result and key ID; verification also
  enforces the expected worker ID.
- Task and result signatures use separate domain prefixes.
- Public/private keys are DER encoded then base64 encoded for environment
  injection. Private keys must never be placed in source control, task payloads,
  database rows, logs, or worker images.

The backend task private key must remain backend-only. A worker must never
receive it. Conversely, the worker's private key stays in that worker's secret
store; only its public key is provided to the backend. Each worker gets a
different keypair and key ID. Key provisioning, secure storage, revocation,
and automated rotation are not implemented yet; the caller must select the
correct trusted key material out of band.

The isolated validator requires:
- SNAKE_BACKEND_ED25519_PUBLIC_KEY_B64
- SNAKE_WORKER_ED25519_PRIVATE_KEY_B64
- SNAKE_WORKER_ID
- SNAKE_WORKER_KEY_ID

The backend's internal issuance function requires the backend private key.
Acknowledgement acceptance requires the expected worker's public key. The
validation result is limited to accepted/rejected and fixes execution_enabled=false.

Task issue-time skew, maximum 300-second task lifetime, expiry, scope revalidation,
durable receipt binding, and one-time receipt consumption remain separate controls.
There is still no network transport or process orchestration connecting backend
and validator. No scan execution is enabled.
