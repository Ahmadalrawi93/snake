from datetime import datetime, timezone
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base

def utcnow():
    return datetime.now(timezone.utc)

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
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    context_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
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


class AIAnalysisEvaluation(Base):
    """Human-only feedback on an AI hypothesis; append-only and separate from triage."""
    __tablename__ = "ai_analysis_evaluations"
    __table_args__ = (
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
