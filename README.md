# SNAKE

AI-assisted security assessment platform for **authorized** bug bounty work.

> Status: Control plane, hardened worker communication, passive evidence pipeline, and an explicitly invoked AI triage adapter. Not an autonomous scanner.

## Implemented
- FastAPI authentication, user-owned projects, and admin-reviewed authorization records.
- Next.js dashboard connected to registration/login, owner-scoped project management, target registration, authorization references, admin review, and immutable scope snapshot creation/validation; scan execution and AI analysis controls are not exposed as working UI actions.
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
- Validation evidence assessment checks human-attested supporting/contradictory evidence, source provenance, expected/observed behavior, and impact context; readiness never means a confirmed vulnerability.
- Finding qualification converts complete, consistent evidence into an unconfirmed human-review candidate, binds assessment counts and provenance IDs to the supplied bundle, and flags repeated category/hypothesis fingerprints; it cannot confirm findings or authorize tests.
- Finding qualification candidates are persisted immutably with exact evidence-bundle JSON and SHA-256, bound to the analysis run context digest; human decisions now require an existing persisted candidate. Candidate persistence structurally checks IDs/digests but does not independently prove evidence truth.
- Human-attested finding impact assessments are persisted as owner-scoped, append-only records bound to the candidate, evidence-bundle digest, and verified analysis provenance. Database constraints keep final severity unassessed, CVSS empty, and execution disabled; incomplete evidence readiness blocks severity suggestions.
- Immutable AI triage history with context/correlation digests, optional provider usage metadata, and owner-scoped read access.
- Human-only hypothesis evaluation with append-only outcomes and conservative precision/coverage metrics.
- Target-aware AI analysis history and strictly isolated human-feedback profiles; target associations are explicit and never inferred.
- Worker can consume an optional operator-provisioned offline passive feed, enforce the task's signed hostname allowlist, and return signed observations through the mTLS transport; it performs no target-network collection, active probing, or vulnerability tests.

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

In a second terminal, start the dashboard:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`. The frontend defaults to the API at
`http://localhost:8000`; configure `NEXT_PUBLIC_API_URL` and
`SNAKE_ALLOWED_ORIGINS` if using different local origins. See
[frontend setup and security notes](frontend/README.md).


## Account authentication security

Browser sessions and API bearer tokens are individually revocable and owner
managed. Password changes revoke all active credentials. Failed password
attempts are persistently throttled per account and server-observed source.
See [browser session and account security](docs/BROWSER_SESSION_SECURITY.md)
for cookie/CSRF requirements, credential lifecycle endpoints, migration order,
rate-limit behavior, and production deployment boundaries.

## Production deployment boundary

The production Compose configuration activates the backend's production
validators, requires exact HTTPS frontend origins, enables secure session
cookies, and binds the API only to host loopback. A separately configured TLS
reverse proxy is mandatory; this repository does not yet ship that proxy.
See [deployment security requirements](infrastructure/DEPLOYMENT_SECURITY.md).

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


See [business logic intelligence](docs/BUSINESS_LOGIC_INTELLIGENCE.md), [cross-surface reasoning](docs/CROSS_SURFACE_REASONING.md), and [validation strategy engine](docs/VALIDATION_STRATEGY_ENGINE.md) and [validation evidence engine](docs/VALIDATION_EVIDENCE_ENGINE.md) for evidence boundaries and confirmation limitations.


See [finding qualification engine](docs/FINDING_QUALIFICATION_ENGINE.md) for candidate rules, deduplication limits, and confirmation boundaries.


See [human finding decisions](docs/HUMAN_FINDING_DECISIONS.md) for API behavior, reviewer attestation limits, and remaining hardening.


See [persisted finding candidates](docs/FINDING_CANDIDATE_PERSISTENCE.md) for candidate storage and trust boundaries.

See [Finding Impact & Severity Assessment](docs/FINDING_IMPACT_ASSESSMENT.md) for human-attested impact claims, immutable assessment history, and severity limitations.

Finding Intelligence compares persisted candidates using category families, normalized title/evidence tokens, source-observation overlap, and normalized route signatures. Cross-category matching requires strong evidence overlap and a shared route. It labels possible duplicates for human review only; it never merges, suppresses, deletes, or confirms candidates. See [Finding Intelligence](docs/FINDING_INTELLIGENCE.md).


## Finding lifecycle and evidence vault

Persisted finding candidates now have an append-only human lifecycle and an encrypted evidence vault. Lifecycle state is derived from immutable transition events; evidence bytes are Fernet-encrypted before database storage and verified by SHA-256 on retrieval. Configure `SNAKE_EVIDENCE_VAULT_FERNET_KEY` through deployment secret management before enabling evidence uploads. Missing keys fail closed. See [Finding Lifecycle & Evidence Vault](docs/FINDING_LIFECYCLE_EVIDENCE_VAULT.md).


## Explicit analysis orchestration

The synchronous service in `backend/app/core/analysis_orchestrator.py` connects DeepSeek analysis, persisted manual-only validation strategy, server-recomputed evidence assessment, candidate qualification, and immutable candidate persistence. It is an explicit service call only; no route, queue, worker, or scanner invokes it automatically. See [Analysis Orchestrator](docs/ANALYSIS_ORCHESTRATOR.md) for trust boundaries and limitations.


## Worker observation provenance

The provenance-safe analysis path rebuilds context from signed worker observations stored in the backend, verifies the original Ed25519 batch signature, binds each observation to its task, target, authorization and scope snapshot, and stores immutable links on the analysis run. Candidate qualification rebuilds that context from the stored links rather than trusting client-provided observations. See [Worker Observation Provenance](docs/WORKER_OBSERVATION_PROVENANCE.md). The worker can now produce signed observations from a pre-collected offline feed; it does not harvest feeds or perform target-network reconnaissance. The mTLS ingestion path is an internal transport adapter, not a public result-ingestion API.


See [Offline Passive Recon Producer](docs/WORKER_RESULT_INGESTION.md) for the bounded feed format, signed scope filtering, replay behavior, and limitations.
