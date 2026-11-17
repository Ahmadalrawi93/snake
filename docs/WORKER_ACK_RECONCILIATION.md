# Worker acknowledgement reconciliation

## Purpose

The administrator-only endpoint reconciles a signed validation acknowledgement
that arrived after the backend recorded a dispatch attempt as `unknown`.
This is not a retry mechanism and does not mark a scan as completed.

## Endpoint

`POST /api/v1/admin/workers/tasks/{task_id}/reconcile`

Authentication: administrator bearer token.

Request body:

```json
{
  "acknowledgement": {
    "result": {
      "task_id": "the-original-task-uuid",
      "envelope_sha256": "64-character-original-envelope-digest",
      "worker_id": "registered-worker-id",
      "outcome": "accepted",
      "validated_at": "2026-11-17T03:50:00Z",
      "execution_enabled": false
    },
    "key_id": "registered-worker-key-id",
    "signature": "ed25519:v1:..."
  }
}
```

The complete signed object is verified using the active registered Ed25519
worker key. The path task ID must match the signed result.

## Acceptance rules

The reconciliation operation requires all of the following:

- a durable task receipt bound to the same worker, key, and envelope digest;
- an unconsumed receipt;
- a latest dispatch attempt whose status is exactly `unknown`;
- a matching worker/key/digest on that attempt;
- a valid Ed25519 signature under the currently active registered key;
- `validated_at` at or after receipt creation (allowing the configured 30-second
  clock skew), strictly before the original receipt expiry, and not in the future
  beyond that skew;
- the result explicitly keeps `execution_enabled=false`.

The backend may receive the acknowledgement after receipt expiry, but it accepts
it only when the worker-signed `validated_at` proves the worker validated the
task inside the original validity window. A late HTTP response by itself is
never sufficient evidence.

The receipt consumption and unknown-to-delivered attempt transition use
conditional database updates in one transaction. The route adds an audit event
to that same transaction. Repeated or concurrent reconciliation cannot consume
the receipt twice. The worker key must still be active; revoked keys fail closed.

## Semantics and limits

A successful response means **delivery/validation acknowledgement reconciled**,
not that reconnaissance ran, a vulnerability was found, or a scan completed.
The job remains non-executable and no scan result is created. The endpoint does
not fetch the worker's SQLite ledger or expose worker storage; an operator must
obtain the original signed acknowledgement through a trusted local procedure
and submit it unchanged.

The current endpoint is an administrator-submitted evidence path, not an
automated worker-to-backend reconciliation channel. Production deployment still
requires operator identity controls, rate limiting, alerting, tested PostgreSQL
transaction behavior, and a secure way to retrieve acknowledgements from workers.
