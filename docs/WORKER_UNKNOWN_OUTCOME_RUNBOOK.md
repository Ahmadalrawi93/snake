# Unknown worker delivery outcome runbook

## When this applies

Use this procedure when the backend records a dispatch attempt as `unknown`,
including a timeout after request transmission, a connection reset after send,
an oversized response, an invalid acknowledgement, or an unexpected HTTP
response. These conditions do not prove that the worker rejected the task.

## Immediate containment

1. Do not retry the task and do not move its job back to `queued`.
2. Keep the job in its reserved/dispatch state and preserve the dispatch-attempt
   row, task ID, worker ID, key ID, envelope digest, and timestamps.
3. Do not create a replacement task ID for the same job while the outcome is
   unresolved.
4. Record the incident and operator handling in the audit/change record.

## Worker-side reconciliation

On the worker host, use the approved administrative access path to inspect the
persistent SQLite replay ledger. Do not expose the ledger through a public API.
For the exact task ID, verify:

- the stored task ID, envelope SHA-256 digest, worker ID, and key ID;
- whether a signed acknowledgement byte sequence was durably committed;
- whether the ledger database and its persistent volume are healthy;
- whether the worker process restarted or the ledger was restored from backup
  after the delivery attempt.

If a matching row exists, retrieve the exact stored acknowledgement through a
controlled local administrative procedure, then verify its Ed25519 signature,
worker/key binding, task digest, and timestamp at the backend. The current
repository does not yet provide a dedicated authenticated reconciliation API;
do not improvise one by exposing SQLite or accepting an operator-supplied
unsigned result.

If no row exists, that alone is not sufficient proof of non-acceptance if the
worker ledger may have been lost, rolled back, replaced, or mounted
ephemerally. Confirm persistent-volume integrity and worker logs before any
decision.

## Resolution

- Matching durable acknowledgement verified: close the attempt as delivered
  through a future audited reconciliation workflow. Until that workflow exists,
  preserve the evidence and do not mutate database rows manually in production.
- Authoritative proof of rejection before acceptance: an operator may authorize
  a new dispatch through a future explicit retry workflow after recording the
  evidence and confirming the original task was not accepted.
- Ambiguous or missing evidence: leave the outcome unknown and escalate. Do not
  retry automatically.

## Engineering gate

Before production dispatch is enabled, implement an authenticated,
role-restricted reconciliation API/command that reads worker-side evidence
without exposing the database, verifies the signed acknowledgement against the
registered active/revoked key policy and receipt digest, writes an immutable
audit event, and supports explicit operator approval. Add tests for lost
ledger, restored backup, revoked keys, duplicate reconciliation, and concurrent
operator actions.
