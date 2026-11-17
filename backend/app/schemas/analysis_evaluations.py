"""Strict human feedback contract for AI-generated hypotheses."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AnalysisEvaluationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    outcome: Literal["confirmed", "false_positive", "inconclusive", "duplicate"]
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    validation_method: str = Field(min_length=3, max_length=80)
    notes: str = Field(default="", max_length=2000)

    @field_validator("validation_method", "notes")
    @classmethod
    def safe_text(cls, value: str) -> str:
        if any(ord(char) < 32 and char not in "\t\n" for char in value) or "\x7f" in value:
            raise ValueError("control characters are not allowed")
        return value.strip()

    @model_validator(mode="after")
    def require_evidence_for_resolved_outcomes(self):
        if self.outcome in {"confirmed", "false_positive"} and not self.evidence_sha256:
            raise ValueError("resolved outcomes require an evidence SHA-256 digest")
        if self.outcome in {"inconclusive", "duplicate"} and self.evidence_sha256 is not None:
            raise ValueError("evidence digest is not accepted for this outcome")
        return self


class AnalysisEvaluationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    analysis_run_id: int
    project_id: int
    evaluator_id: int
    outcome: Literal["confirmed", "false_positive", "inconclusive", "duplicate"]
    evidence_sha256: str | None
    validation_method: str
    notes: str
    created_at: datetime


class AnalysisEvaluationMetrics(BaseModel):
    reviewed: int
    confirmed: int
    false_positive: int
    inconclusive: int
    duplicate: int
    resolved_precision: float | None
    resolution_coverage: float
