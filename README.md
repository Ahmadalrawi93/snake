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
- Registered HTTPS worker endpoints, DNS destination validation, TLS/mTLS transport adapter, certificate pinning, and a bounded HTTPS worker listener; deployment still requires production network and certificate operations.
- Durable worker-side replay ledger and read-only acknowledgement export; late signed acknowledgements can be reconciled through an audited admin endpoint.
- Immutable signed worker observation records with owner-scoped read access; no direct API path to fabricate worker observations.
- Bounded deterministic analysis context, provenance-preserving deduplication, and passive evidence correlation.
- Target-scoped application intelligence inventory of observed hosts, technology clues, and route surfaces, with source IDs and no active probing.
- Explicit DeepSeek-compatible JSON triage adapter with fixed HTTPS provider URL, bounded requests/responses, no tools or retries, strict output validation, and evidence-reference checks.
- Deterministic pre-provider redaction of common credential patterns; this is not a complete DLP system.
- Evidence-only cross-surface reasoning links authentication, object-resource, and sensitive-action route observations on the same host; it never infers shared controls or confirms vulnerabilities.
- Evidence-bound validation strategy ranks manual review questions, records missing evidence and prerequisites, and remains non-executable; no requests, commands, or payloads are generated.
- Immutable AI triage history with context/correlation digests, optional provider usage metadata, and owner-scoped read access.
- Human-only hypothesis evaluation with append-only outcomes and conservative precision/coverage metrics.
- Target-aware AI analysis history and strictly isolated human-feedback profiles; target associations are explicit and never inferred.
- Worker currently returns validation-only acknowledgements; it does not perform reconnaissance or vulnerability tests.

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

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md),
[worker communication](docs/WORKER_COMMUNICATION.md),
[observation triage](docs/OBSERVATION_TRIAGE.md),
[analysis context](docs/ANALYSIS_CONTEXT.md),
[evidence correlation](docs/EVIDENCE_CORRELATION.md),
[DeepSeek adapter](docs/DEEPSEEK_ANALYSIS_ADAPTER.md),
[analysis redaction](docs/ANALYSIS_REDACTION.md),
[worker runtime](docs/WORKER_RUNTIME.md),
[task authentication](docs/WORKER_TASK_AUTHENTICATION.md), and
[replay protection](docs/WORKER_REPLAY_PROTECTION.md).


See [human AI hypothesis evaluation](docs/AI_ANALYSIS_EVALUATION.md) for outcome definitions and metric caveats.

See [intelligence feedback](docs/INTELLIGENCE_FEEDBACK.md) for aggregation rules and limitations.

See [application intelligence profile](docs/APPLICATION_INTELLIGENCE.md) for its evidence limits and route classification rules.


See [business logic intelligence](docs/BUSINESS_LOGIC_INTELLIGENCE.md), [cross-surface reasoning](docs/CROSS_SURFACE_REASONING.md), and [validation strategy engine](docs/VALIDATION_STRATEGY_ENGINE.md) for evidence boundaries and manual review limitations.
