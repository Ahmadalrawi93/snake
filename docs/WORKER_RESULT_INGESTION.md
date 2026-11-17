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

This is an internal persistence service, not a network ingestion endpoint. Do not expose it directly through a public HTTP route. A future endpoint must authenticate the worker through the registered mTLS endpoint and certificate pin, enforce strict request framing and body limits, then call this service. The worker HTTPS listener can now optionally consume a pre-collected local JSON feed and transmit a signed, scope-filtered observation batch. It does not collect data from target networks; feed acquisition remains an external, separately governed process. `execution_enabled` remains false and no active scanning or exploit validation is performed.


## Offline passive feed producer

Set `SNAKE_WORKER_PASSIVE_FEED_FILE` to a provisioned JSON file inside the worker container. The file is a JSON array of records with `hostname`, `kind` (`hostname`, `url`, `dns_record`, `technology`, or `http_header`), `value`, `evidence`, `source`, and timezone-aware `observed_at`. It is limited to 1 MiB and 500 records, must be a regular non-symlink file, and must not be group- or world-writable. Mount it read-only from a trusted feed-preparation process.

For every task, the producer verifies the backend signature first, then filters each record against the approved hostname rules embedded in that signed task. URL records must be HTTP(S), match their declared hostname, and contain no credentials, query, or fragment. Out-of-scope records are discarded. Remaining records are deduplicated, assigned deterministic task-bound observation IDs, and signed with the worker Ed25519 key. DNS, technology, and header records retain their hostname association in the evidence field. The exact full task response is persisted in the worker replay ledger, so a retry returns the same acknowledgement and observation batch even if the feed file changes later.

This is an offline adapter, not a feed harvester: it performs no DNS lookup, HTTP request, socket operation, subprocess, or shell execution. It does not prove that a feed source is accurate or that its claimed collection method was passive. Operators must validate feed provenance and legal collection authority separately. The worker remains non-executable and every observation remains `unconfirmed_observation`.


The backend also independently revalidates each observation's hostname against the immutable approved snapshot before including it in AI analysis. Hostname and URL observations are checked directly; DNS, technology, and HTTP-header observations must carry an explicit `hostname=<host>;` evidence binding. IP-only observations without a hostname binding are excluded from analysis. Worker-side filtering is not treated as a trust boundary.
