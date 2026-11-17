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
`worker_dispatch_attempts`. An attempt is committed as `started` before network
I/O. It can close as `delivered`, `failed`, or `unknown`.
Only a definite `failed` outcome permits another attempt, and that retry reuses
the same signed task ID and envelope. A timeout/ambiguous result becomes
`unknown` and blocks automatic retry until reconciled. Worker key status,
receipt digest, receipt expiry, and one-time consumption are checked before
starting an attempt. The receipt binds the worker ID and key ID selected at signing time,
so a valid task cannot be redirected to a different registered worker.

The transport adapter calls this ledger. It uses explicit connect/read timeouts,
a fixed task endpoint, bounded response bodies (64 KiB maximum), and no automatic
retry. Once request transmission begins, ambiguous errors and unexpected HTTP
responses are recorded as `unknown`; only failures proven before network delivery
may be marked `failed`. Database concurrency behavior still requires testing on
the intended production PostgreSQL deployment.

## Worker endpoint registry

Administrators can now provision one HTTPS origin per worker identity. The registry
stores the canonical origin, exact TLS server name, and SHA-256 certificate
fingerprint. Registration rejects plain HTTP, IP-literal hosts, localhost/internal
suffixes, embedded credentials, non-root paths, query strings, fragments, and
mismatched TLS names. Endpoint revocation is one-way and audited. These records
are configuration only: no code connects to them yet. The backend resolves registered hostnames through the existing network destination
policy. It rejects the entire DNS answer if any address is private, loopback,
link-local, reserved, or otherwise non-global, and returns validated public
addresses for pinning. Revoked or missing endpoint records cannot be resolved.
An internal mTLS transport adapter now dials one returned IP directly, preserves
the registered DNS name for TLS SNI/hostname verification, requires a client
certificate, verifies the exact SHA-256 server-certificate fingerprint, and
re-checks endpoint/key state immediately before sending.

## Deliberately not connected yet

There is currently **no enabled production delivery path** between the API and a worker:
- the mTLS adapter exists as an internal callable only; no API route, scheduler,
  worker polling endpoint, or background dispatcher invokes it;
- the worker runtime still consumes signed JSON from stdin, not HTTP;
- no broker, message queue, or automatic process/container launcher;
- no automatic network retry or automatic requeue (only the internal attempt ledger exists);
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
7. Retry only after a persisted definite failure, reusing the exact signed task ID
   and envelope. Unknown outcomes require reconciliation; never reuse a consumed
   receipt or silently reset a reserved job.
8. Verify the acknowledgement signature, active key status, worker identity,
   task digest, timestamp window, and one-time receipt before accepting it.
9. Keep execution disabled until the worker sandbox, egress policy, approval gates,
   and result-validation pipeline are independently implemented and tested.

## Next implementation gate

Next, define and implement the worker-side authenticated HTTPS listener and a
signed acknowledgement response protocol, then add end-to-end TLS tests for
certificate mismatch, client identity rejection, timeouts/unknown outcomes,
duplicate delivery, revoked endpoints/keys, malformed/oversized responses, and
replayed acknowledgements. Production PostgreSQL concurrency tests remain required.
