from datetime import datetime, timezone
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class AuthFailedAttemptBucket(Base):
    """Persistent, privacy-preserving failed-authentication rate-limit bucket."""
    __tablename__ = "auth_failed_attempt_buckets"
    __table_args__ = (
        CheckConstraint("length(key_sha256) = 64", name="ck_auth_failed_bucket_digest_length"),
        CheckConstraint("attempts >= 1", name="ck_auth_failed_attempts_positive"),
    )
    key_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ApiAccessToken(Base):
    """Revocable non-browser bearer token; only a digest of its JWT jti is stored."""
    __tablename__ = "api_access_tokens"
    __table_args__ = (
        UniqueConstraint("token_id_sha256", name="uq_api_access_tokens_token_digest"),
        CheckConstraint("length(token_id_sha256) = 64", name="ck_api_access_tokens_token_digest_length"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    token_id_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class UserSession(Base):
    """Revocable browser session; only a digest of the JWT jti is stored."""
    __tablename__ = "user_sessions"
    __table_args__ = (
        UniqueConstraint("token_id_sha256", name="uq_user_sessions_token_digest"),
        CheckConstraint("length(token_id_sha256) = 64", name="ck_user_sessions_token_digest_length"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    token_id_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    authorizations: Mapped[list["Authorization"]] = relationship(back_populates="project")
    targets: Mapped[list["Target"]] = relationship(back_populates="project")

class Authorization(Base):
    __tablename__ = "authorizations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    reference: Mapped[str] = mapped_column(String(500), nullable=False)
    starts_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    expires_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    scope_rules: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    project: Mapped["Project"] = relationship(back_populates="authorizations")

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_type: Mapped[str] = mapped_column(String(30), default="url")
    status: Mapped[str] = mapped_column(String(20), default="registered")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    project: Mapped["Project"] = relationship(back_populates="targets")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(80), nullable=False)
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ScopeSnapshot(Base):
    __tablename__ = "scope_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False, index=True)
    authorization_id: Mapped[int] = mapped_column(ForeignKey("authorizations.id"), nullable=False, index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False, index=True)
    scope_snapshot_id: Mapped[int] = mapped_column(ForeignKey("scope_snapshots.id"), nullable=False, index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    profile: Mapped[str] = mapped_column(String(40), nullable=False, default="passive_recon")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class WorkerTaskReceipt(Base):
    """Durable one-time task ledger; it never grants permission to execute a scan."""
    __tablename__ = "worker_task_receipts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), unique=True, nullable=False)
    envelope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledgement_outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)
    acknowledgement_worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    acknowledgement_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class WorkerKey(Base):
    """Public verification key registered for one worker identity/version."""
    __tablename__ = "worker_keys"
    __table_args__ = (
        UniqueConstraint("worker_id", "key_id", name="uq_worker_keys_worker_key"),
        UniqueConstraint("fingerprint_sha256", name="uq_worker_keys_fingerprint"),
        CheckConstraint("status IN ('active', 'revoked')", name="ck_worker_keys_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(String(2048), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False, index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)



class WorkerDispatchAttempt(Base):
    """Append-only delivery attempt history for one already-signed task."""
    __tablename__ = "worker_dispatch_attempts"
    __table_args__ = (
        UniqueConstraint("task_id", "attempt_number", name="uq_worker_attempt_task_number"),
        CheckConstraint(
            "status IN ('started', 'delivered', 'failed', 'unknown')",
            name="ck_worker_attempt_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("worker_task_receipts.task_id"), nullable=False, index=True
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    envelope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="started")
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)



class WorkerEndpoint(Base):
    """Admin-provisioned HTTPS endpoint pinned to a worker TLS certificate."""
    __tablename__ = "worker_endpoints"
    __table_args__ = (
        UniqueConstraint("worker_id", name="uq_worker_endpoint_worker"),
        CheckConstraint("status IN ('active', 'revoked')", name="ck_worker_endpoint_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    tls_server_name: Mapped[str] = mapped_column(String(253), nullable=False)
    certificate_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active", index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)



class WorkerObservationBatchReceipt(Base):
    """Idempotency record for one authenticated worker result batch per task."""
    __tablename__ = "worker_observation_batch_receipts"
    __table_args__ = (
        UniqueConstraint("task_id", name="uq_worker_observation_batch_task"),
        CheckConstraint("observation_count >= 0 AND observation_count <= 500", name="ck_worker_batch_observation_count"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[str] = mapped_column(String(36), ForeignKey("worker_task_receipts.task_id"), nullable=False)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    envelope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    batch_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class WorkerObservationRecord(Base):
    """Immutable passive-recon evidence; never a confirmed vulnerability finding."""
    __tablename__ = "worker_observations"
    __table_args__ = (
        UniqueConstraint("observation_id", name="uq_worker_observation_external_id"),
        CheckConstraint(
            "kind IN ('hostname', 'url', 'ip', 'technology', 'http_header', 'dns_record')",
            name="ck_worker_observation_kind",
        ),
        CheckConstraint(
            "classification = 'unconfirmed_observation'",
            name="ck_worker_observation_unconfirmed_only",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("worker_task_receipts.task_id"), nullable=False, index=True
    )
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    envelope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    batch_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    batch_signature: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    batch_payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    classification: Mapped[str] = mapped_column(
        String(40), nullable=False, default="unconfirmed_observation"
    )


class AIAnalysisRun(Base):
    """Immutable, provenance-bound AI triage output; never a confirmed finding."""
    __tablename__ = "ai_analysis_runs"
    __table_args__ = (
        CheckConstraint("status IN ('completed')", name="ck_ai_analysis_run_status"),
        CheckConstraint("disposition = 'requires_independent_validation'",
                        name="ck_ai_analysis_requires_validation"),
        CheckConstraint("execution_enabled = false", name="ck_ai_analysis_execution_disabled"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True, index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    context_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provenance_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlations_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False, default="deepseek")
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="completed")
    disposition: Mapped[str] = mapped_column(
        String(50), nullable=False, default="requires_independent_validation"
    )
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provider_request_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)



class AnalysisRunObservationLink(Base):
    """Immutable provenance edge from an analysis run to a worker-signed observation."""
    __tablename__ = "analysis_run_observation_links"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "observation_record_id", name="uq_analysis_run_observation_link"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("ai_analysis_runs.id"), nullable=False, index=True)
    observation_record_id: Mapped[int] = mapped_column(ForeignKey("worker_observations.id"), nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    envelope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    batch_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    batch_signature: Mapped[str] = mapped_column(String(128), nullable=False)
    scope_snapshot_id: Mapped[int] = mapped_column(ForeignKey("scope_snapshots.id"), nullable=False)
    scope_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    authorization_id: Mapped[int] = mapped_column(ForeignKey("authorizations.id"), nullable=False)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AIAnalysisEvaluation(Base):
    """Human-only feedback on an AI hypothesis; append-only and separate from triage."""
    __tablename__ = "ai_analysis_evaluations"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "evaluator_id", name="uq_ai_analysis_evaluation_actor_run"),
        CheckConstraint(
            "outcome IN ('confirmed', 'false_positive', 'inconclusive', 'duplicate')",
            name="ck_ai_analysis_evaluation_outcome",
        ),
        CheckConstraint(
            "(outcome IN ('confirmed', 'false_positive') AND evidence_sha256 IS NOT NULL) OR "
            "(outcome IN ('inconclusive', 'duplicate'))",
            name="ck_ai_analysis_evaluation_evidence",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_run_id: Mapped[int] = mapped_column(
        ForeignKey("ai_analysis_runs.id"), nullable=False, index=True
    )
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    evaluator_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation_method: Mapped[str] = mapped_column(String(80), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)



class HumanFindingDecision(Base):
    """Append-only human decision for a specific candidate fingerprint."""
    __tablename__ = "human_finding_decisions"
    __table_args__ = (
        UniqueConstraint(
            "analysis_run_id", "candidate_fingerprint", "evaluator_id",
            name="uq_human_finding_decision_reviewer_candidate",
        ),
        CheckConstraint(
            "outcome IN ('confirmed', 'false_positive', 'inconclusive', 'duplicate')",
            name="ck_human_finding_decision_outcome",
        ),
        CheckConstraint("reviewer_attested = true", name="ck_human_finding_reviewer_attested"),
        CheckConstraint(
            "(outcome IN ('confirmed', 'false_positive') AND evidence_sha256 IS NOT NULL) OR "
            "(outcome IN ('inconclusive', 'duplicate'))",
            name="ck_human_finding_decision_evidence",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_run_id: Mapped[int] = mapped_column(
        ForeignKey("ai_analysis_runs.id"), nullable=False, index=True
    )
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    evaluator_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    candidate_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation_method: Mapped[str] = mapped_column(String(80), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reviewer_attested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class FindingCandidateRecord(Base):
    """Immutable persisted candidate and exact evidence bundle."""
    __tablename__ = "finding_candidate_records"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "candidate_fingerprint", name="uq_finding_candidate_run_fingerprint"),
        CheckConstraint("qualification = 'human_review_candidate'", name="ck_finding_candidate_reviewable_only"),
        CheckConstraint("finding_status = 'unconfirmed'", name="ck_finding_candidate_unconfirmed_only"),
        CheckConstraint("execution_enabled = false", name="ck_finding_candidate_execution_disabled"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("ai_analysis_runs.id"), nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    candidate_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    qualification: Mapped[str] = mapped_column(String(40), nullable=False)
    finding_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unconfirmed")
    evidence_bundle_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_bundle_json: Mapped[str] = mapped_column(Text, nullable=False)
    qualification_json: Mapped[str] = mapped_column(Text, nullable=False)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)



class FindingImpactAssessmentRecord(Base):
    """Append-only human impact assessment bound to an immutable candidate and evidence."""
    __tablename__ = "finding_impact_assessments"
    __table_args__ = (
        UniqueConstraint("candidate_id", "assessment_sha256", name="uq_finding_impact_candidate_digest"),
        CheckConstraint("final_severity = 'not_assessed'", name="ck_finding_impact_final_severity_unassessed"),
        CheckConstraint("cvss_vector IS NULL", name="ck_finding_impact_cvss_unassigned"),
        CheckConstraint("execution_enabled = false", name="ck_finding_impact_execution_disabled"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("finding_candidate_records.id"), nullable=False, index=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("ai_analysis_runs.id"), nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    evidence_bundle_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    claims_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_json: Mapped[str] = mapped_column(Text, nullable=False)
    final_severity: Mapped[str] = mapped_column(String(20), nullable=False, default="not_assessed")
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class FindingLifecycleEvent(Base):
    """Append-only state transition; current status is derived from the latest event."""
    __tablename__ = "finding_lifecycle_events"
    __table_args__ = (
        CheckConstraint("from_status IN ('new','under_review','needs_more_evidence','confirmed','rejected','duplicate')", name="ck_finding_lifecycle_from"),
        CheckConstraint("to_status IN ('new','under_review','needs_more_evidence','confirmed','rejected','duplicate')", name="ck_finding_lifecycle_to"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("finding_candidate_records.id"), nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    related_candidate_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class EvidenceArtifact(Base):
    """Encrypted, immutable evidence bytes linked to a persisted candidate."""
    __tablename__ = "finding_evidence_artifacts"
    __table_args__ = (
        CheckConstraint("size_bytes > 0 AND size_bytes <= 1048576", name="ck_finding_evidence_size"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("finding_candidate_records.id"), nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String(180), nullable=False)
    media_type: Mapped[str] = mapped_column(String(80), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class InvestigationMemoryRecord(Base):
    """Append-only, project/target-scoped hypothesis history; never suppresses review."""
    __tablename__ = "investigation_memory_records"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "strategy_id", name="uq_investigation_memory_run_strategy"),
        CheckConstraint("execution_enabled = false", name="ck_investigation_memory_execution_disabled"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False, index=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("ai_analysis_runs.id"), nullable=False, index=True)
    strategy_id: Mapped[str] = mapped_column(String(80), nullable=False)
    hypothesis_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    hypothesis_text: Mapped[str] = mapped_column(String(1000), nullable=False)
    candidate_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    observation_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class LocalReconRun(Base):
    """Persisted result of one bounded local HTTP collection pass."""
    __tablename__ = "local_recon_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('completed', 'partial', 'failed')",
            name="ck_local_recon_run_status",
        ),
        CheckConstraint(
            "pages_requested >= 0 AND pages_requested <= 10",
            name="ck_local_recon_pages_requested",
        ),
        CheckConstraint(
            "observation_count >= 0 AND observation_count <= 250",
            name="ck_local_recon_observation_count",
        ),
        CheckConstraint(
            "execution_enabled = false",
            name="ck_local_recon_execution_disabled",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False, index=True)
    scope_snapshot_id: Mapped[int] = mapped_column(ForeignKey("scope_snapshots.id"), nullable=False, index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    pages_requested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class LocalReconObservation(Base):
    """Redacted metadata-only HTTP evidence from a local recon run."""
    __tablename__ = "local_recon_observations"
    __table_args__ = (
        UniqueConstraint("observation_id", name="uq_local_recon_observation_id"),
        CheckConstraint(
            "kind IN ('url', 'http_header')",
            name="ck_local_recon_observation_kind",
        ),
        CheckConstraint(
            "classification = 'unconfirmed_observation'",
            name="ck_local_recon_observation_unconfirmed",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("local_recon_runs.id"), nullable=False, index=True)
    observation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    host_key: Mapped[str] = mapped_column(String(253), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    classification: Mapped[str] = mapped_column(
        String(40), nullable=False, default="unconfirmed_observation"
    )
