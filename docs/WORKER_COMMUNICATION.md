# Worker communication boundary

## Current implementation

SNAKE can prepare a short-lived, scope-revalidated task envelope, sign it with the
backend Ed25519 private key, and reserve the corresponding queued job exactly once.
Task issuance now requires the destination worker's (worker_id, key_id) to exist
in the database-backed registry with status active. A revoked or unknown key is
rejected before scope preparation or job reservation.

The one-shot worker validator accepts signed JSON on stdin. A separate minimal
HTTPS listener now accepts the same signed task at the fixed
`POST /internal/v1/tasks` path, requires a client certificate issued by the
configured backend CA and matching an exact SHA-256 client-certificate pin,
validates the backend Ed25519 signature and worker/key binding, then uses a
worker-side SQLite replay ledger before returning a signed validation-only
acknowledgement. The ledger commits the task ID, envelope digest, worker/key
identity, and exact acknowledgement bytes atomically. An identical retry returns
the stored acknowledgement (even after a process restart); reuse of a task ID
with changed content or identity is rejected. Expiry is enforced on first
acceptance, not on an already accepted duplicate. It caps
request bodies at 64 KiB, applies a five-second socket read timeout, bounds
concurrent handler threads, and accepts only HTTP/1.1 with exactly one non-empty Host header. It rejects
ambiguous framing (duplicate Content-Length/Content-Type/Host), Transfer-Encoding,
Content-Encoding, Trailer, Upgrade, non-ASCII or non-decimal lengths, and
Expect/continue rather than attempting to normalize them. The backend mTLS adapter now requires the worker's
signed acknowledgement, verifies it against the active registered public key,
and consumes the durable receipt once.

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
are consumed by the internal mTLS transport adapter; registration itself never initiates a connection. The backend resolves registered hostnames through the existing network destination
policy. It rejects the entire DNS answer if any address is private, loopback,
link-local, reserved, or otherwise non-global, and returns validated public
addresses for pinning. Revoked or missing endpoint records cannot be resolved.
An internal mTLS transport adapter now dials one returned IP directly, preserves
the registered DNS name for TLS SNI/hostname verification, requires a client
certificate and configured CA trust, verifies the exact SHA-256 server-certificate
fingerprint, and re-checks endpoint/key state immediately before sending. It
validates the returned signed acknowledgement rather than treating HTTP 200 as
proof of acceptance.

## Deliberately not connected yet

There is currently **no enabled production delivery path** between the API and a worker:
- the mTLS adapter and HTTPS listener exist as internal components only; no API
  route, scheduler, worker polling endpoint, or background dispatcher invokes them;
- the existing Compose worker service still runs the isolated stdin/stdout validator;
  the HTTPS listener is not launched or exposed by Compose;
- no broker, message queue, or automatic process/container launcher;
- no automatic network retry or automatic requeue (only the internal attempt ledger exists);
- no scan execution (the protocol requires execution_enabled=false).

Do not interpret a successful task-issuance call as successful delivery or execution.
A job reserved for dispatch must not be silently returned to queued.

## Remaining transport contract

Before enabling delivery in a deployment, the operator must:
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

## Verified integration boundary

A local end-to-end integration test now exercises the backend adapter against
the HTTPS listener over real TLS. Public-DNS policy resolution is stubbed to a
test-only public address while the test connection dials loopback, preserving
the registered TLS hostname, CA validation, and exact certificate pin. The test
covers task signing, mTLS client authentication, worker signature verification,
signed acknowledgement verification, durable attempt closure, and one-time
receipt consumption. A separate listener test rejects an unpinned backend
client certificate.

This proves the local transport protocol path, not production deployment
readiness. The backend now has a real mTLS integration test in which the worker accepts
and validates a task but deliberately delays its acknowledgement beyond the
backend deadline. The backend records `unknown` and refuses a second dispatch.
Remaining gates include revoked endpoint/key races under PostgreSQL, malformed
and oversized response coverage, production PostgreSQL concurrency tests,
network firewall/egress enforcement, certificate lifecycle/rotation, and
operator-controlled deployment.
The listener now defaults to loopback and rejects wildcard bind addresses; an
operator must explicitly select a non-wildcard interface for remote connectivity. The HTTPS listener remains validation-only;
no API route, scheduler, or background dispatcher invokes it, and scan execution
remains disabled. The listener requires `SNAKE_WORKER_REPLAY_DB_PATH`; point it
at a durable writable filesystem location. The current hardened Compose
`worker-validator` remains read-only and isolated and does not mount this ledger
or launch the HTTPS listener. A future listener deployment must explicitly
provision a persistent volume with restrictive ownership/permissions and backup/
retention policy; ephemeral container storage defeats restart replay protection.


## Worker-side replay ledger

The HTTPS listener's SQLite ledger uses `BEGIN IMMEDIATE`, a primary-key
constraint on task ID, a 10-second busy timeout, WAL mode, and
`synchronous=FULL`. Signature and worker/key binding are verified before ledger
access. A new task must pass expiry validation before its acknowledgement is
created and committed. Concurrent identical deliveries serialize: one creates
the acknowledgement and the others return its exact stored bytes. A task ID
collision with a different envelope digest or worker/key identity fails closed.
This is validation idempotency only; it does not make future scan execution
idempotent. The ledger path must be persistent and writable in any listener
deployment, and SQLite concurrency/durability must be re-evaluated if multiple
worker processes or hosts share the same task namespace.


## Certificate rotation gate

The current registries and listener configuration support one active worker
server-certificate fingerprint per endpoint and one pinned backend client
certificate fingerprint per worker listener. There is no overlapping-pin
rotation protocol. Rotate certificates only in a controlled maintenance window:
stop any delivery process (none is enabled by default), prepare and validate the
new certificate chain and private key, update the worker's trusted backend CA
and exact backend-client certificate pin, update the backend endpoint's server
certificate fingerprint, deploy the matching certificates on both sides, then
run a real mTLS handshake and signed-task/acknowledgement validation before
restoring connectivity. Keep the previous material offline for a bounded rollback
window; never leave both old and new private keys mounted longer than necessary.
If any step fails, keep delivery stopped and restore the complete previous
configuration as a unit. Do not attempt zero-downtime rotation with the current
single-pin schema. Track certificate owner, serial number, SHA-256 fingerprint,
not-before/not-after dates, deployment window, and revocation status in the
operator's change record; never commit private keys or CA private material.


The replay-ledger tests also verify transaction rollback when acknowledgement
signing fails or returns an invalid empty/non-bytes payload. Since no durable
acknowledgement was committed or returned in those cases, a later valid
acceptance can proceed without leaving a poisoned task ID reservation.
