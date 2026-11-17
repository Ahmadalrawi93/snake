# Atomic reservation and replay barrier

The internal worker-claim module adds two database primitives:

- reserve_task_receipt uses a conditional SQL UPDATE requiring queued status, disabled
  execution, the fixed profile, and the matching snapshot. The job transition and receipt
  insert commit in one transaction. Unique task_id and job_id constraints prevent duplicate
  issuance, including after the receipt expires.
- consume_task_receipt conditionally updates only a matching, unconsumed, unexpired receipt.
  Exactly one caller can change consumed_at from NULL. The digest binds consumption to the
  exact canonical task envelope.

Receipts remain durable after consumption and expiry. Do not delete them as a cleanup
shortcut. Re-queueing requires a separately designed attempt identity and audited reset policy.

## Deliberate limits

These are internal primitives, not HTTP endpoints. They do not authenticate a transport,
verify an HMAC signature, revalidate authorization/scope, contact a worker, return scan
results, or enable execution. A future caller must verify HMAC and rerun complete
scope/authorization/network checks before dispatch. Envelopes remain execution_enabled=false.
No worker consumes these receipts and no network traffic occurs.

The conditional update relies on transactional database semantics. Production concurrency
and locking behavior must be tested against the selected database. The current deployment
remains SQLite-oriented; PostgreSQL is not yet configured.
