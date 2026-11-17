"""Constrained AI triage output for unconfirmed recon observations."""
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


_TEXT = r"^[^\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]{1,2000}$"


class ObservationTriage(BaseModel):
    """A hypothesis only; this contract cannot represent a confirmed finding."""

    model_config = ConfigDict(extra="forbid", strict=True)

    category: Literal[
        "authentication", "authorization", "information_exposure",
        "injection", "security_misconfiguration", "business_logic", "other"
    ]
    hypothesis: str = Field(min_length=1, max_length=2000, pattern=_TEXT)
    supporting_observation_ids: list[UUID] = Field(min_length=1, max_length=30)
    missing_evidence: list[str] = Field(default_factory=list, max_length=20)
    validation_questions: list[str] = Field(min_length=1, max_length=15)
    confidence: Literal["low", "medium", "high"]
    disposition: Literal["requires_independent_validation"] = "requires_independent_validation"

    @model_validator(mode="after")
    def unique_references(self):
        if len(self.supporting_observation_ids) != len(set(self.supporting_observation_ids)):
            raise ValueError("duplicate supporting observation reference")
        return self
