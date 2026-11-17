# Atomic reservation, acknowledgement binding, and replay barrier

## Task issuance

issue_signed_worker_task is an internal backend function. It:

1. Re-reads job, project, target, authorization, and scope snapshot through the dispatch gate.
2. Creates a short-lived envelope with execution disabled.
3. Signs the envelope with the backend Ed25519 private key, binding the intended worker ID and that worker's key ID.
4. Atomically changes the job from queued to dispatch_reserved and inserts a unique durable receipt.

The backend private key remains backend-only. Workers receive the backend public
key to verify tasks, never the backend private key. Every worker has a distinct
Ed25519 keypair. The worker's private key signs acknowledgements; the backend
verifies with that worker's public key. Private keys are injected out of band and
are not stored in the database.

Unique task and job IDs on the receipt table prevent duplicate issuance for the
same job. A reserved job is not silently returned to the queue if later signing
or delivery fails; recovery requires a separately designed audited attempt model.

## Acknowledgement acceptance

accept_worker_acknowledgement requires all of the following:

- Valid Ed25519 signature verified with the expected worker's public key.
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

There is no worker-key registry, KMS/secret-manager integration, automated
provisioning, key revocation endpoint, or rotation workflow. The caller must
select the correct worker public key from trusted configuration. Environment
variables are a local-development convenience, not production key management.

No worker scan execution or outbound network traffic is enabled. Production
database concurrency must be tested against PostgreSQL; current development
remains SQLite-oriented.
