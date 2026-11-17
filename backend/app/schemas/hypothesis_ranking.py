"""Deterministic ranking and exact-hypothesis deduplication; prioritization only."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class HypothesisRankedItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    strategy_id: str
    category: str
    hypothesis_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    rank_score: int = Field(ge=0, le=100)
    rank: int = Field(ge=1, le=100)
    duplicate_of_strategy_id: str | None = None
    duplicate_count: int = Field(ge=0, le=100)
    supporting_observation_count: int = Field(ge=0, le=500)
    priority_basis: str
    ranking_factors: list[str] = Field(max_length=8)
    disposition: Literal["prioritization_only_requires_human_review"] = "prioritization_only_requires_human_review"

class HypothesisRankingReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    items: list[HypothesisRankedItem] = Field(max_length=100)
    duplicate_group_count: int = Field(ge=0, le=100)
    execution_enabled: Literal[False] = False
    confidence_score: Literal[None] = None
    vulnerability_severity: Literal[None] = None
