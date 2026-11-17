"""Cross-hypothesis observation reuse report; reuse is not independent corroboration."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class EvidenceReuseItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    strategy_id: str
    shared_observation_count: int = Field(ge=0, le=500)
    shared_observation_ids: list[str] = Field(max_length=500)
    reuse_ratio_percent: int = Field(ge=0, le=100)
    interpretation: Literal["no_reuse", "partial_reuse", "complete_reuse"]
    warning: Literal["shared_observations_are_not_independent_evidence"] = "shared_observations_are_not_independent_evidence"

class CrossHypothesisEvidenceReuseReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    current_strategy_id: str
    current_observation_count: int = Field(ge=0, le=500)
    reused_with_other_hypotheses: list[EvidenceReuseItem] = Field(max_length=99)
    unique_observation_count: int = Field(ge=0, le=500)
    memory_status: Literal["current_analysis_run_only_no_persistent_history"]
    execution_enabled: Literal[False] = False
    confidence_score: Literal[None] = None
