# Idempotent Worker Observation Batch Ingestion

A task may produce exactly one signed observation batch. The backend verifies the registered active Ed25519 key, consumed task receipt, accepted acknowledgement, worker/key identity, envelope digest, and collection time before persistence.

## Atomicity and replay behavior

- A durable batch receipt has a unique task ID and stores the canonical batch digest, signature, identity, envelope digest, and observation count.
- An exact retry for the same task and same signed batch returns the original count without inserting observations again.
- A different batch for an already-receipted task is rejected. A task cannot append a second batch.
- The receipt and all observation rows are inserted inside one database savepoint. A duplicate observation ID rejects the entire batch; the service does not roll back unrelated caller work.
- The caller owns the outer transaction and must commit after successful ingestion. Failed batches must not be committed.
- Empty signed batches are permitted and still consume the task's one-batch slot.

## Security boundary and limitations

This is an internal persistence service, not a network ingestion endpoint. Do not expose it directly through a public HTTP route. A future endpoint must authenticate the worker through the registered mTLS endpoint and certificate pin, enforce strict request framing and body limits, then call this service. The existing worker HTTPS listener still emits validation-only acknowledgements; it does not yet produce or transmit reconnaissance observations. `execution_enabled` remains false and no active scanning or exploit validation is performed.
