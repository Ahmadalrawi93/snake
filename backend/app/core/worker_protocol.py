"""Strict, non-executable worker message contract.

This module defines data that may be dispatched after a real worker exists.
It deliberately contains no shell command, script, executable path, or argv field.
All execution remains disabled until independent dispatch and network controls exist.
"""
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class WorkerTaskEnvelope(BaseModel):
    """Allowlisted task metadata; never an instruction to execute arbitrary code."""

    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: UUID
    job_id: int = Field(gt=0)
    scope_snapshot_id: int = Field(gt=0)
    scope_snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile: Literal["passive_recon"]
    target_url: HttpUrl
    issued_at: datetime
    expires_at: datetime
    execution_enabled: Literal[False] = False

    @model_validator(mode="after")
    def validate_time_window(self):
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("worker timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("task expiry must be after issue time")
        return self


def ensure_not_expired(task: WorkerTaskEnvelope, now: datetime | None = None) -> None:
    """Reject stale task envelopes; this does not authorize or execute a task."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    current_utc = current.astimezone(timezone.utc)
    issued_utc = task.issued_at.astimezone(timezone.utc)
    expires_utc = task.expires_at.astimezone(timezone.utc)
    if issued_utc > current_utc + timedelta(seconds=30):
        raise ValueError("worker task issue time is in the future")
    if expires_utc - issued_utc > timedelta(seconds=300):
        raise ValueError("worker task lifetime exceeds 300 seconds")
    if current_utc >= expires_utc:
        raise ValueError("worker task expired")
    if task.execution_enabled is not False:
        raise ValueError("worker execution is disabled")


class WorkerValidationResult(BaseModel):
    """A validation-only acknowledgement; it cannot claim scan completion."""

    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: UUID
    envelope_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    worker_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._-]+$")
    outcome: Literal["accepted", "rejected"]
    validated_at: datetime
    execution_enabled: Literal[False] = False

    @model_validator(mode="after")
    def validate_timestamp(self):
        if self.validated_at.tzinfo is None:
            raise ValueError("worker result timestamp must be timezone-aware")
        return self
