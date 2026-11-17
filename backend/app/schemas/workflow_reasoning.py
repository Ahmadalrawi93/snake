"""Conservative workflow-transition reasoning from passive route observations."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class WorkflowActionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: str = Field(min_length=1, max_length=40)
    route_template: str = Field(min_length=1, max_length=1024)
    observation_ids: list[str] = Field(min_length=1, max_length=500)

class WorkflowTransitionHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253)
    resource: str = Field(min_length=1, max_length=80)
    observed_actions: list[str] = Field(min_length=2, max_length=12)
    action_evidence: list[WorkflowActionEvidence] = Field(min_length=2, max_length=24)
    possible_transition_pairs: list[str] = Field(min_length=1, max_length=30)
    ordering_status: Literal["unknown_from_passive_observations"] = "unknown_from_passive_observations"
    validation_questions: list[str] = Field(min_length=1, max_length=8)
    supporting_observation_ids: list[str] = Field(min_length=1, max_length=500)
    disposition: Literal["requires_independent_validation"] = "requires_independent_validation"

class WorkflowReasoningReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    report_version: Literal["1"] = "1"
    hypotheses: list[WorkflowTransitionHypothesis] = Field(max_length=500)
    execution_enabled: Literal[False] = False
    confirmed: Literal[False] = False
    limitations: Literal["Passive route observations cannot establish action order, state preconditions, allowed roles, HTTP methods, or business-rule enforcement."] = "Passive route observations cannot establish action order, state preconditions, allowed roles, HTTP methods, or business-rule enforcement."
