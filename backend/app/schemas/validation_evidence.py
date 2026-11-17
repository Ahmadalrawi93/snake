"""Human-recorded validation evidence; never a confirmed vulnerability finding."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ValidationEvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    evidence_id: UUID
    evidence_type: Literal[
        "program_policy", "expected_behavior", "observed_behavior",
        "authorized_test_account", "impact_context", "owner_confirmation",
        "technical_documentation", "other"
    ]
    relationship: Literal["supports", "contradicts", "context_only"]
    statement: str = Field(min_length=8, max_length=1200)
    source_label: str = Field(min_length=2, max_length=120)
    observation_ids: list[UUID] = Field(max_length=100)
    recorded_at: datetime
    human_attested: Literal[True]

    @model_validator(mode="after")
    def validate_record(self):
        if self.recorded_at.tzinfo is None:
            raise ValueError("evidence timestamp must be timezone-aware")
        if self.evidence_type in {"expected_behavior", "observed_behavior", "impact_context"} and not self.observation_ids:
            raise ValueError("behavior and impact evidence must reference source observations")
        if self.relationship == "context_only" and self.evidence_type == "observed_behavior":
            raise ValueError("observed behavior must support or contradict the hypothesis")
        return self


class ValidationEvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    strategy_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    analysis_context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    items: list[ValidationEvidenceItem] = Field(min_length=1, max_length=100)
    reviewer_note: str = Field(default="", max_length=1000)
    reviewed_at: datetime

    @model_validator(mode="after")
    def validate_bundle(self):
        if self.reviewed_at.tzinfo is None:
            raise ValueError("review timestamp must be timezone-aware")
        ids = [item.evidence_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate evidence_id")
        if any(item.recorded_at > self.reviewed_at for item in self.items):
            raise ValueError("evidence cannot be recorded after review time")
        return self


class ValidationEvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    strategy_id: str
    evidence_status: Literal["insufficient", "mixed", "consistent"]
    impact_status: Literal["not_documented", "documented_not_independently_verified"]
    readiness: Literal["more_evidence_required", "human_review_ready"]
    supporting_evidence_count: int = Field(ge=0)
    contradicting_evidence_count: int = Field(ge=0)
    context_evidence_count: int = Field(ge=0)
    required_gaps: list[str] = Field(max_length=10)
    evidence_ids: list[UUID] = Field(max_length=100)
    observation_ids: list[UUID] = Field(max_length=500)
    disposition: Literal["requires_independent_human_validation"] = "requires_independent_human_validation"
    execution_enabled: Literal[False] = False
