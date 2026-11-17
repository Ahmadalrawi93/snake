# Worker communication boundary

## Current implementation

SNAKE can prepare a short-lived, scope-revalidated task envelope, sign it with the
backend Ed25519 private key, and reserve the corresponding queued job exactly once.
Task issuance now requires the destination worker's (worker_id, key_id) to exist
in the database-backed registry with status active. A revoked or unknown key is
rejected before scope preparation or job reservation.

The worker validator accepts a signed JSON message on stdin, verifies the backend
signature and worker/key binding, checks expiry, and emits a signed validation-only
acknowledgement on stdout. The backend verifies acknowledgements against the active
registered public key and consumes the durable receipt once.

## Durable dispatch attempt ledger

The backend now has an internal attempt state machine backed by
`worker_dispatch_attempts`. An attempt is committed as `started` before any
future network I/O. It can close as `delivered`, `failed`, or `unknown`.
Only a definite `failed` outcome permits another attempt, and that retry reuses
the same signed task ID and envelope. A timeout/ambiguous result becomes
`unknown` and blocks automatic retry until reconciled. Worker key status,
receipt digest, receipt expiry, and one-time consumption are checked before
starting an attempt.

This ledger is implemented as internal primitives only; no HTTP or socket
transport calls them yet. Database concurrency behavior still requires testing
on the intended production PostgreSQL deployment.

## Deliberately not connected yet

There is currently **no network transport** between the API and a worker:
- no worker polling or callback HTTP endpoint;
- no outbound HTTP client, mTLS channel, broker, or message queue;
- no automatic process/container launcher;
- no delivery retry or automatic requeue;
- no scan execution (the protocol requires execution_enabled=false).

Do not interpret a successful task-issuance call as successful delivery or execution.
A job reserved for dispatch must not be silently returned to queued.

## Required transport contract

A future transport adapter must:
1. Select a worker only from an administratively provisioned registry entry.
2. Use authenticated TLS (prefer mutual TLS) with certificate identity bound to the
   registered worker identity; never accept a caller-provided arbitrary worker URL.
3. Send only the signed, bounded JSON task envelope; reject oversized messages and
   unknown fields at both ends.
4. Revalidate the immutable scope snapshot, authorization status/expiry, target
   linkage, and destination DNS/IP policy immediately before any network operation.
5. Use explicit connect/read deadlines and bounded response sizes.
6. Treat timeouts as an **unknown delivery outcome**, not proof of non-delivery.
   Persist every attempt and its outcome before implementing retries.
7. Make retries use new task IDs and durable attempt records with idempotency rules;
   never reuse a consumed receipt or silently reset a reserved job.
8. Verify the acknowledgement signature, active key status, worker identity,
   task digest, timestamp window, and one-time receipt before accepting it.
9. Keep execution disabled until the worker sandbox, egress policy, approval gates,
   and result-validation pipeline are independently implemented and tested.

## Next implementation gate

Build the durable dispatch-attempt state machine and worker endpoint identity
provisioning before enabling any network transport. Then add transport integration
tests for TLS identity mismatch, timeout/unknown outcome, duplicate delivery,
revoked keys, malformed/oversized responses, and replayed acknowledgements.
