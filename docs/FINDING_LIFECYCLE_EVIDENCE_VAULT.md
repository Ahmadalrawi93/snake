# Finding Lifecycle & Evidence Vault

## Lifecycle

Lifecycle changes are append-only events, not updates to the candidate row. The current state is derived from the latest event; a candidate with no events is `new`.

Allowed transitions:
- `new -> under_review`
- `under_review -> needs_more_evidence | confirmed | rejected | duplicate`
- `needs_more_evidence -> under_review | rejected`
- `confirmed`, `rejected`, and `duplicate` are terminal in this version. Terminal transitions require a matching recorded decision by the same authenticated reviewer. Confirmation additionally requires the decision's evidence digest to match an artifact already stored in the encrypted vault. Rejection requires a recorded `false_positive` decision; duplicate status requires a recorded `duplicate` decision and a different candidate in the same project.

Every transition includes the expected current state (optimistic concurrency guard), actor, rationale and timestamp. Duplicate status requires a different candidate fingerprint already present in the same project. Lifecycle `confirmed` is an explicit human workflow state, not an AI result and not cryptographic proof that the reported issue is valid. The API does not automatically transition from a decision record; a human must explicitly submit the lifecycle transition.

## Evidence Vault

- Uploads are JSON Base64 payloads, decoded limit 1 MiB per artifact.
- Fernet authenticated encryption is applied before database persistence.
- The encryption key is supplied only through `SNAKE_EVIDENCE_VAULT_FERNET_KEY`; it is never stored in the database.
- Missing/invalid key fails closed. Generate a key offline with Python's `Fernet.generate_key()` and store it in the deployment secret manager.
- SHA-256 is computed over original bytes; downloads decrypt and verify digest and exact size. Downloads are also written to the audit log.
- Records are append-only and project-owner scoped. Content is not returned by metadata endpoints.
- MIME type is metadata only; downloads use `application/octet-stream` and `nosniff`.
- Filename path components are stripped. No filesystem path is accepted or constructed.
- No malware scanning, OCR, automatic evidence interpretation, external object storage, key rotation, or per-project envelope encryption exists yet. Database backups contain ciphertext, but key backup and rotation are operator responsibilities.

## API

- `POST /api/v1/finding-candidates/{id}/lifecycle`
- `GET /api/v1/finding-candidates/{id}/lifecycle`
- `POST /api/v1/finding-candidates/{id}/evidence`
- `GET /api/v1/finding-candidates/{id}/evidence`
- `GET /api/v1/finding-evidence/{id}/content`

All endpoints require authentication and enforce project ownership. These endpoints do not enable scanning or change the worker execution policy.
