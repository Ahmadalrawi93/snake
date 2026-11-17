# Validation Evidence Engine

This engine evaluates **human-attested evidence records** against one existing manual validation strategy and the exact analysis-context digest.

## Evidence contract
Each evidence item records a bounded type, whether it supports, contradicts, or only contextualizes the hypothesis, a short statement, source label, timestamp, and source observation IDs. The `human_attested=true` field is an assertion supplied by the caller, not cryptographic proof of reviewer identity; a future authenticated review API must bind the record to the logged-in reviewer. The schema deliberately has no fields for request payloads, credentials, commands, arbitrary URLs, or state-changing actions.

## Deterministic gates
- Strategy ID and context digest must match.
- Every strategy/evidence observation reference must exist in the supplied analysis context.
- Written program policy, expected behavior, observed behavior, impact context, supporting observed behavior, and linkage to the strategy's original observations are required for human-review readiness.
- Contradictory evidence yields `mixed`, not a positive conclusion.
- Impact can only be labeled `documented_not_independently_verified`.

## Critical limitation
`human_review_ready` means the evidence bundle has the required recorded categories; it does **not** mean the hypothesis is true, impact is proven, or a vulnerability is confirmed. Every assessment retains `requires_independent_human_validation` and `execution_enabled=false`.

This is currently a pure internal function. No API endpoint, database persistence, scanner invocation, network request, or automatic finding creation is added.


## Evidence coverage (not confidence or severity)

The deterministic coverage assessor reports whether documentary elements are present:
written program policy, expected behavior, supporting observed behavior, an
authorized test-account record, impact context, and traceable source observation
references. It returns a 0–100 **coverage score** and a missing-elements list.

The score is not a probability, confidence estimate, CVSS score, exploitability
rating, or proof that a statement is true. A complete score only means that the
listed evidence categories were recorded. The assessment explicitly leaves
impact independently verified as false and has no field for vulnerability
severity. Contradictory evidence is counted and remains a blocker in the
existing qualification workflow.

The candidate orchestration result now includes this coverage assessment
alongside the existing validation evidence assessment and qualification. The
coverage function cross-checks evidence IDs, observation IDs, and relationship
counts against the exact bundle rather than trusting detached assessment
summaries. No automated testing or finding confirmation is triggered.


## Evidence Gap Intelligence

The candidate pipeline also returns a deterministic, strategy-bound evidence-gap
report. Gaps are derived from the exact human evidence bundle and verified
analysis context references; model-authored gap descriptions are not accepted.
Each gap identifies the affected hypothesis, required evidence type, minimum
acceptable record, related evidence/observation IDs, and safe manual collection
guidance. Missing evidence is explicitly **not evidence of absence**.

Written policy, expected behavior, source-linked supporting behavior,
designated test-account context, impact context, strategy linkage, and source
traceability are treated as independent documentary requirements. Contradictory
records create a separate hard blocker and remain linked for review. A record
that exists but is contradictory or only contextual does not satisfy a
supporting-evidence requirement.

Acquisition guidance is limited to official documentation, program-owner
clarification, designated test identities, and records already obtained inside
written authorization. The engine creates no network requests, test commands,
payloads, or state changes. Evidence gaps are not a vulnerability verdict and
do not independently qualify a finding.


Hard evidence gaps are also passed into candidate qualification. Any unresolved
hard blocker (including missing designated test-account evidence or unresolved
contradictions) forces `insufficient_evidence`, even if an older assessment
summary would otherwise appear ready. The qualification function validates the
gap report's strategy binding and records each blocking gap category. This
prevents the gap report from being merely advisory while leaving promotion
logic unchanged.


## Evidence Acquisition Planner

The candidate pipeline returns a deterministic manual acquisition plan alongside
the evidence-gap report. Each step maps to one validated gap and identifies an
objective, acceptable authoritative sources, prerequisites, dependencies, and
a strict safety boundary. The ordering prioritizes current written program
authorization, expected behavior, and designated test context before reviewing
technical behavior or impact records.

The planner does not generate HTTP requests, payloads, shell commands, test
cases, credentials, or state-changing actions. It only directs a human reviewer
to existing immutable records, official documentation, program-owner
clarification, or explicitly designated test context. It rejects gap references
that do not belong to the supplied evidence bundle. Its output is a collection
workflow, not proof of vulnerability, authorization, or exploitability.


## Evidence Quality & Source Diversity

The pipeline reports documentary quality separately from evidence coverage, confidence, severity, and finding qualification. It counts supporting, contradictory, and contextual records; detects exact duplicate record signatures and shared observation-reference sets; and groups supporting records by their caller-supplied source labels.

A source label is **not an authenticated source identity**. Multiple labels are therefore reported as `multiple_labeled_sources_unverified`, never as verified independent sources. Repeated records and reused observation references generate warnings. Contradictions remain explicit and lower the quality band; they are never discarded or averaged away. These metrics do not establish truth, causality, exploitability, or impact, and do not independently promote or reject a candidate.


## Hypothesis Ranking & Deduplication

The orchestrator now emits a deterministic ranking report for the persisted validation-strategy plan. Scores are review-queue heuristics based on declared strategy priority, distinct supporting observation references, prerequisites, and security-boundary/business-logic category. They are not exploitability, likelihood, confidence, impact, or severity scores.

Exact normalized hypothesis text within the same category is grouped under one representative strategy; materially different hypotheses remain separate even when they concern the same route or category. The report preserves duplicate counts and the representative strategy reference. Ranking never executes tests, confirms vulnerabilities, or independently changes finding qualification. Human review and the existing evidence gates remain mandatory.


## Cross-Hypothesis Evidence Reuse

The candidate pipeline compares observation references in the current human-attested evidence bundle with sibling validation strategies from the same persisted AI analysis run. It reports shared references, overlap ratio, and references unique to the current strategy. Reused observations are explicitly not independent corroboration. This first version is deliberately run-local: it does not claim persistent investigation memory, and it does not automatically suppress, merge, or qualify hypotheses. No network activity or evidence acquisition is performed.


## Persistent Investigation Memory

The candidate pipeline records a normalized hypothesis fingerprint and its supporting observation references for each strategy. Historical matches are returned only when both project_id and target_id match; the current analysis run is excluded and history is bounded to the latest 50 records. The report distinguishes shared observations from newly referenced observations. It does not suppress review, infer a false positive, or treat historical AI output as truth. Human decision outcomes are intentionally marked as not linked until a separately verified strategy-to-candidate decision binding exists. Apply Alembic migration 0020 before deploying this schema to an existing database.


### Human Review Memory Linkage

Investigation memory now stores the candidate fingerprint produced by the same strategy pipeline. When a later run finds the same normalized hypothesis on the same project and target, it retrieves append-only human finding decisions only through that exact candidate fingerprint and analysis-run identity. Multiple reviewer outcomes are surfaced without collapsing disagreement. Decisions are historical context only: false-positive, duplicate, inconclusive, and confirmed outcomes never automatically suppress a new review. Strategies that did not produce a persisted human-review candidate remain explicitly unlinked to finding decisions.


## Investigation Learning Engine

The persistent investigation-memory report aggregates only reviewer-attested decisions linked to the exact prior candidate fingerprint and analysis run, within the same project and target. Each historical run is counted once; conflicting reviewer outcomes are handled conservatively, with a confirmed outcome taking precedence over false-positive for that run. At least three distinct prior reviewed runs with false-positive outcomes and no confirmed outcomes produce a bounded -10 review-priority adjustment. Mixed outcomes, insufficient history, confirmed history, inconclusive and duplicate-only history do not reduce priority. The adjustment affects ordering only: no strategy is removed, no testing is skipped, and no vulnerability likelihood or confidence is inferred. The model's existing AI-generated hypotheses remain untrusted until human review.
