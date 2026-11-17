# Worker Task Response and Result Transport

The worker HTTPS endpoint returns a strict `WorkerTaskResponse` JSON envelope containing:
- `acknowledgement`: the worker's Ed25519-signed validation acknowledgement;
- `observation_batch`: optional worker Ed25519-signed observation batch.

The listener optionally reads a trusted, pre-collected local JSON feed when `SNAKE_WORKER_PASSIVE_FEED_FILE` is configured. It filters feed records against the approved scope rules embedded in the signed task, creates deterministic observation IDs, and signs the batch with the worker Ed25519 key. It does not collect data from target networks, perform DNS/HTTP requests, or run active tests. Without the optional feed, `observation_batch` remains null. The backend transport verifies and consumes the acknowledgement first; when a signed batch is present, it validates the batch against the consumed task receipt and active registered worker key, persists it through the idempotent batch store, and commits before marking the dispatch attempt delivered.

The response remains bounded by the existing 64 KiB limit. mTLS, pinned destination IP, DNS revalidation, TLS hostname verification, exact certificate pinning, strict HTTP framing, and Ed25519 task/acknowledgement signatures remain required.

If a response contains an invalid batch after a valid acknowledgement, the task acknowledgement remains consumed but the dispatch is not reported as delivered; the attempt is conservatively recorded as unknown. There is no automatic retry after ambiguous delivery.

## Not yet implemented

- No passive reconnaissance producer is connected to the listener.
- No observation batch is currently emitted by the production listener.
- No task execution, active probing, or exploit validation is enabled.
- A future producer must enforce the approved snapshot allowlist before signing any observation, and backend provenance checks remain mandatory.
