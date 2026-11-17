"""Persistent investigation memory comparison report."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class PriorInvestigationMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    analysis_run_id: int
    strategy_id: str
    shared_observation_count: int = Field(ge=0, le=500)
    new_observation_count: int = Field(ge=0, le=500)
    disposition: Literal["new_observations_available", "previously_seen_no_new_observations"]
    human_outcomes: list[Literal["confirmed", "false_positive", "inconclusive", "duplicate"]] = Field(max_length=20)
    review_state: Literal["human_reviewed", "not_reviewed"]

class InvestigationMemoryReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    current_strategy_id: str
    hypothesis_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    prior_matches: list[PriorInvestigationMatch] = Field(max_length=50)
    memory_scope: Literal["same_project_and_same_target_only"]
    review_suppressed: Literal[False] = False
    execution_enabled: Literal[False] = False
