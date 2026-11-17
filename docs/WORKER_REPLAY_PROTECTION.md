# Atomic reservation, acknowledgement binding, and replay barrier

## Task issuance

`issue_signed_worker_task` is an internal backend function. It:

1. Re-reads job, project, target, authorization, and scope snapshot through the dispatch gate.
2. Creates a short-lived envelope with execution disabled.
3. Atomically changes the job from `queued` to `dispatch_reserved` and inserts a unique durable receipt in one transaction.
4. Signs the canonical envelope with the dedicated worker HMAC secret.

A unique task ID and unique job ID on the receipt table prevent duplicate issuance for the same job. A reserved job is not silently returned to the queue if later signing or delivery fails; recovery requires a separately designed audited attempt model.

## Acknowledgement acceptance

`accept_worker_acknowledgement` requires all of the following:

- Valid HMAC signature for the acknowledgement domain.
- Exact expected worker ID label.
- Existing unconsumed receipt matching task ID and canonical envelope digest.
- Acknowledgement timestamp within the receipt creation/expiry window and bounded clock skew.
- Receipt is still unexpired.

Only then does a conditional SQL UPDATE consume the receipt and persist outcome, worker ID label, and validation timestamp. A second acknowledgement cannot consume it again. The result is a validation acknowledgement only, never a scan-completion state.

## Deliberate limits

These functions are internal; there is no HTTP endpoint, network transport, queue consumer, or process orchestration connecting the backend to the isolated validator. The current validator uses a configured HMAC secret but has no database receipt access. Therefore a signed validator response must be passed to the backend acceptance function by a future transport integration; replay protection is not yet end-to-end across the process boundary.

The worker ID is an expected label, not a strong cryptographic identity when multiple workers share one secret. Production requires per-worker secrets or asymmetric identities, authenticated transport, secret rotation, and audit controls.

No worker scan execution or outbound network traffic is enabled. Production database concurrency must be tested against PostgreSQL; current development remains SQLite-oriented.
