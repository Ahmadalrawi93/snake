"""Deterministic, project-scoped summaries of human-reviewed AI hypotheses."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class FeedbackPattern(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    category: str
    reviewed: int = Field(ge=1)
    confirmed: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    duplicate: int = Field(ge=0)
    resolved_precision: float | None
    recommendation: Literal["retain", "deprioritize", "insufficient_evidence"]


class IntelligenceFeedbackProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    profile_version: Literal["1"] = "1"
    project_id: int
    target_id: int | None = None
    evaluated_runs: int = Field(ge=0)
    patterns: list[FeedbackPattern] = Field(max_length=2000)
    notice: Literal[
        "Human-review history is a prioritization signal only; it never confirms findings or authorizes testing."
    ] = "Human-review history is a prioritization signal only; it never confirms findings or authorizes testing."
