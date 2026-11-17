# Worker Result Pipeline

## Current boundary

SNAKE accepts a deliberately narrow data contract for passive-recon observations.
It is not a vulnerability-finding API and does not execute scans.

- Each batch is signed with the registered worker's Ed25519 private key.
- The backend verifies the active registered public key and signature.
- The batch must bind to a consumed task receipt: task ID, envelope digest,
  worker ID, and key ID must all match.
- Observation IDs are globally unique. Replays or collisions are rejected.
- The batch digest is stored with every observation to preserve provenance.
- Every row is classified as `unconfirmed_observation`; a database constraint
  rejects other classifications. Migration `0011` adds database triggers that
  reject UPDATE and DELETE for SQLite and PostgreSQL. Unsupported database
  dialects fail the migration closed rather than silently losing this guarantee.
- The schema has no severity, exploitability, confirmation, command, script,
  or arbitrary fetch instruction fields.

## Observation kinds

The allowlist is hostname, URL, IP, technology, HTTP header, and DNS record.
Values are bounded and control characters are rejected. Evidence is bounded
text and is treated as untrusted input, not as instructions to an AI agent.

## Important limitations

The persistence service is currently an internal backend function. It is not
exposed as an HTTP endpoint and is not wired into the worker HTTPS listener.
The current worker still emits validation acknowledgements only; it does not
perform reconnaissance or produce these batches yet.

Before enabling ingestion over the network, implement a separately authenticated
result transport, strict request-size and rate limits, transaction/audit handling,
retention controls, and end-to-end tests. The append-only triggers intentionally
mean evidence correction must be represented as a new, linked record in a future
supersession model; operators must not edit or delete source evidence. Any future promotion to a vulnerability
candidate must be a separate workflow with independent evidence validation.
No observation may become a confirmed vulnerability solely because a worker or
LLM labels it that way.

`execution_enabled=false` remains mandatory.


## Owner-scoped evidence API

Authenticated project owners can read evidence for a scan job:

`GET /api/v1/scan-jobs/{job_id}/observations?limit=50&offset=0`

- The route checks job ownership through the owning project before querying evidence.
- Pagination is bounded to 1–200 rows per request.
- Results are ordered newest-first and retain worker/key, task digest, batch digest,
  source, timestamps, and the fixed `unconfirmed_observation` classification.
- A job outside the caller's project returns 404; the endpoint does not expose
  cross-project existence.
- This is read-only. No finding promotion or scan execution endpoint is provided.
