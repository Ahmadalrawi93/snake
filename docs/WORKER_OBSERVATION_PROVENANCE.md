# Worker Observation Provenance

## Trusted input boundary

The provenance-safe entry point is `execute_persisted_observation_analysis` in `backend/app/core/analysis_orchestrator.py`. It does not accept a client-supplied analysis context. It loads records from the database for one authenticated project owner and target.

Eligible observations must be linked through:
- a consumed worker task receipt with an `accepted` acknowledgement from the same worker;
- a passive-recon ScanJob with execution disabled;
- the exact target and project;
- an active scope snapshot whose canonical JSON digest is re-verified;
- an approved, currently valid authorization;
- a registered worker public key and a valid Ed25519 signature over the canonical full observation batch.

## Stored proof

The ingestion store persists the canonical signed batch payload, its signature, digest, worker/key identity, task ID, and envelope digest with each observation. This permits later signature re-verification instead of trusting a previous boolean check.

Each AI analysis run receives:
- `provenance_sha256`;
- `source_observation_count`;
- immutable `analysis_run_observation_links` that bind every observation to project, target, task, worker/key, envelope, signed batch, scope snapshot digest, and authorization.

The provenance link table is append-only at the database level. The run's context digest is computed from the context rebuilt from these records.

## Candidate qualification

Candidate qualification now requires a provenance-bound analysis run. It rebuilds the analysis context from the run's immutable observation links, re-verifies the signed batches using the historical registered public keys, checks the snapshot digests, and compares the rebuilt context digest to the analysis run. The context argument supplied by a caller is not trusted for the actual assessment.

Historical verification keys remain in the registry after revocation; revocation blocks new ingestion but does not erase the ability to audit old signatures.

## Provenance inspection API

Authenticated project owners can inspect the source chain at `GET /api/v1/analysis-runs/{analysis_run_id}/provenance`. It returns observation identifiers and values, worker/task identity, signed-batch digests, scope snapshot digest, and authorization ID. It does not return private keys or raw batch signatures.

## Limits

- The worker HTTPS listener currently returns a validation-only acknowledgement; it does not itself run reconnaissance or produce observation batches. The observation ingestion store is a backend service boundary, not yet a production HTTPS ingestion endpoint.
- A worker signature proves which registered key signed the submitted batch, not that each observation is factually correct.
- The current scope policy is hostname allowlist based. DNS pinning and outbound enforcement do not make this an active scanner.
- No scan execution, exploit validation, or automatic vulnerability confirmation is enabled.
