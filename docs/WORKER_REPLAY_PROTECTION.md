# Atomic reservation, acknowledgement binding, and replay barrier

## Task issuance

issue_signed_worker_task is an internal backend function. It:

1. Re-reads job, project, target, authorization, and scope snapshot through the dispatch gate.
2. Creates a short-lived envelope with execution disabled.
3. Signs the envelope for an explicit worker ID and key ID using that worker's unique secret.
4. Atomically changes the job from queued to dispatch_reserved and inserts a unique durable receipt.

The caller is responsible for selecting the worker secret and key ID from trusted
operator configuration. Secrets are not stored in the database. Unique task and
job IDs on the receipt table prevent duplicate issuance for the same job.

A reserved job is not silently returned to the queue if later signing or delivery
fails; recovery requires a separately designed audited attempt model.

## Acknowledgement acceptance

accept_worker_acknowledgement requires all of the following:

- Valid HMAC signature using the expected worker's unique secret.
- Exact expected worker ID and key ID.
- Existing unconsumed receipt matching task ID and canonical envelope digest.
- Acknowledgement timestamp within the receipt creation/expiry window and bounded clock skew.
- Receipt is still unexpired.

Only then does a conditional SQL UPDATE consume the receipt and persist outcome,
worker ID label, and validation timestamp. A second acknowledgement cannot
consume it again. The result is a validation acknowledgement only, never a
scan-completion state.

## Deliberate limits

These functions are internal; there is no HTTP endpoint, network transport,
queue consumer, or process orchestration connecting the backend to the isolated
validator. The validator cannot access the database receipt ledger. Therefore
replay protection is not yet end-to-end across the process boundary.

Worker secrets are independently provisioned out of band. key_id supports
explicit key-version selection, but there is no worker-key registry, KMS/secret
manager integration, automated rotation, revocation endpoint, or provisioning
workflow. Environment variables are only a local-development mechanism.

No worker scan execution or outbound network traffic is enabled. Production
database concurrency must be tested against PostgreSQL; current development
remains SQLite-oriented.
