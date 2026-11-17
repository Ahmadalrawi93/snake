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
- Every row is hard-classified as `unconfirmed_observation`; the database
  constraint prevents changing this table into a confirmed finding.
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
retention controls, and end-to-end tests. Any future promotion to a vulnerability
candidate must be a separate workflow with independent evidence validation.
No observation may become a confirmed vulnerability solely because a worker or
LLM labels it that way.

`execution_enabled=false` remains mandatory.
