# Worker task and acknowledgement authentication

SNAKE uses Ed25519 asymmetric signatures rather than a shared HMAC secret.

- The backend signs canonical task payloads with its Ed25519 private key.
- Each worker receives only the backend public key, so a compromised worker
  cannot mint backend-authorized tasks.
- Each worker signs validation acknowledgements with its own Ed25519 private
  key. The backend verifies using that worker's registered public key.
- Task signatures bind the envelope, intended worker ID, and key ID.
  Acknowledgement signatures bind the result and key ID; verification also
  enforces the expected worker ID.
- Task and result signatures use distinct domain-separation prefixes.
- Keys are DER encoded then base64 encoded for environment injection.

The backend private key must remain backend-only. A worker must never receive it.
The worker private key stays in that worker's secret store. The worker public key
is registered in the backend database by an administrator; it is public material.
Every worker needs a distinct keypair and key ID.

## Worker key administration

Admin-only endpoints:
- POST /api/v1/admin/workers/{worker_id}/keys — register a public key.
- GET /api/v1/admin/workers/keys — list registered key metadata and fingerprints.
- POST /api/v1/admin/workers/{worker_id}/keys/{key_id}/revoke — revoke a key.

The registry validates Ed25519 public-key type, computes a canonical SHA-256
fingerprint, rejects duplicate worker/key IDs and duplicate public keys, and
allows only one-way revocation. A revoked key cannot authenticate acknowledgements.
Registering a replacement requires a fresh keypair and a new key ID. All
registration and revocation actions are written to the audit log.

KMS-backed private-key storage, secure automated provisioning, rotation
orchestration, and automated revocation are not implemented. The backend task
private key and each worker private key must be injected through trusted secret
storage. Private keys must never be stored in the worker-key database table,
source control, task payloads, logs, or container images.

## Key generation

Generate DER keys with OpenSSL. Keep the files outside the repository and restrict
permissions:
```sh
umask 077
openssl genpkey -algorithm ED25519 -out backend-ed25519-private.pem
openssl pkey -in backend-ed25519-private.pem -pubout -out backend-ed25519-public.pem
openssl genpkey -algorithm ED25519 -out worker-01-private.pem
openssl pkey -in worker-01-private.pem -pubout -out worker-01-public.pem
```

Export the DER-encoded keys as base64 values:
```sh
openssl pkey -in backend-ed25519-private.pem -outform DER | base64 -w0
openssl pkey -pubin -in backend-ed25519-public.pem -outform DER | base64 -w0
openssl pkey -in worker-01-private.pem -outform DER | base64 -w0
openssl pkey -pubin -in worker-01-public.pem -outform DER | base64 -w0
```

The backend receives its own private key. A worker receives only the backend
public key and its own private key. The worker requires
SNAKE_BACKEND_ED25519_PUBLIC_KEY_B64, SNAKE_WORKER_ED25519_PRIVATE_KEY_B64,
SNAKE_WORKER_ID, and SNAKE_WORKER_KEY_ID.

The validation result is limited to accepted/rejected and fixes
execution_enabled=false. Task expiry, scope revalidation, durable receipt binding,
and one-time receipt consumption remain separate controls. There is no network
transport or process orchestration connecting backend and validator. No scan
execution is enabled.
