# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Control plane, hardened worker communication, passive evidence pipeline, and an explicitly invoked AI triage adapter. Not an autonomous scanner.

## Implemented
- FastAPI authentication, user-owned projects, and admin-reviewed authorization records.
- Immutable SHA-256 scope snapshots and scope revalidation before dispatch preparation.
- DNS/IP destination policy and redirect-hop validation foundations; no outbound requests.
- Persistent scan jobs that remain queued with execution disabled.
- Strict worker task envelope with a fixed passive profile, expiry, and no arbitrary commands.
- Validation-only Docker worker: non-root, read-only, resource-limited, and network-isolated.
- Ed25519 asymmetric authentication: backend signs tasks; each worker signs acknowledgements with its own keypair.
- Admin-only worker public-key registry with duplicate-key protection, fingerprinting, audit events, and one-way revocation.
- Internal issuance revalidates scope and reserves jobs once; acknowledgement verification resolves the active worker key from the registry and consumes the durable receipt once.
- Registered HTTPS worker endpoints, DNS destination validation, TLS/mTLS transport adapter, certificate pinning, and a bounded HTTPS worker listener; deployment still requires production network and certificate operations.\n- Durable worker-side replay ledger and read-only acknowledgement export; late signed acknowledgements can be reconciled through an audited admin endpoint.\n- Immutable signed worker observation records with owner-scoped read access; no direct API path to fabricate worker observations.\n- Bounded deterministic analysis context, provenance-preserving deduplication, and passive evidence correlation.\n- Explicit DeepSeek-compatible JSON triage adapter with fixed HTTPS provider URL, bounded requests/responses, no tools or retries, strict output validation, and evidence-reference checks.\n- Deterministic pre-provider redaction of common credential patterns; this is not a complete DLP system.\n- Immutable AI triage history with context/correlation digests, optional provider usage metadata, and owner-scoped read access.\n- Worker currently returns validation-only acknowledgements; it does not perform reconnaissance or vulnerability tests.

## Local setup
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

## Security boundary

The backend private signing key must never leave the backend. A worker receives
only the backend public key and its own private key. The backend stores the
worker's public key in the database registry; private keys are never stored there.
Administrators can register, list, and revoke worker public keys through the
admin API. Replacing a key requires a new key ID and keypair. KMS-backed storage,
automated provisioning, and automated rotation are not implemented.

The validator reads one signed message from stdin and emits a signed validation
acknowledgement. It has no network, database receipt access, queue consumer, or
scan adapter. This is not production-ready. Socket-level IP pinning, per-request
scope checks, egress enforcement, real transport, and scan execution remain
unimplemented.

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md),\n[worker communication](docs/WORKER_COMMUNICATION.md),\n[observation triage](docs/OBSERVATION_TRIAGE.md),\n[analysis context](docs/ANALYSIS_CONTEXT.md),\n[evidence correlation](docs/EVIDENCE_CORRELATION.md),\n[DeepSeek adapter](docs/DEEPSEEK_ANALYSIS_ADAPTER.md),\n[analysis redaction](docs/ANALYSIS_REDACTION.md),
[worker runtime](docs/WORKER_RUNTIME.md),
[task authentication](docs/WORKER_TASK_AUTHENTICATION.md), and
[replay protection](docs/WORKER_REPLAY_PROTECTION.md).
