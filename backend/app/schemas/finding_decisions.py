"""Authenticated human decisions for specific finding candidates."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class HumanFindingDecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    candidate_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    outcome: Literal["confirmed", "false_positive", "inconclusive", "duplicate"]
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    validation_method: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_]{2,79}$")
    notes: str = Field(default="", max_length=2000)
    reviewer_attested: Literal[True]

    @field_validator("validation_method", "notes")
    @classmethod
    def safe_text(cls, value: str) -> str:
        if any(ord(char) < 32 and char not in "\t\n" for char in value) or "\x7f" in value:
            raise ValueError("control characters are not allowed")
        return value.strip()

    @model_validator(mode="after")
    def validate_evidence(self):
        if self.outcome in {"confirmed", "false_positive"} and not self.evidence_sha256:
            raise ValueError("confirmed and false-positive decisions require an evidence digest")
        if self.outcome in {"inconclusive", "duplicate"} and self.evidence_sha256 is not None:
            raise ValueError("evidence digest is not accepted for this outcome")
        return self


class HumanFindingDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    analysis_run_id: int
    project_id: int
    evaluator_id: int
    candidate_fingerprint: str
    outcome: Literal["confirmed", "false_positive", "inconclusive", "duplicate"]
    evidence_sha256: str | None
    validation_method: str
    notes: str
    reviewer_attested: bool
    created_at: datetime
