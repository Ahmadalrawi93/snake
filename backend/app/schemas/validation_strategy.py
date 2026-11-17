"""Manual-only validation strategy contracts; no executable scan instructions."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class ValidationStrategyItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    strategy_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    category: Literal[
        "authentication_boundary", "object_authorization",
        "sensitive_action_authorization", "workflow_integrity",
        "information_exposure", "injection", "configuration_review", "general_review"
    ]
    priority: Literal["high", "medium", "low"]
    priority_basis: str = Field(min_length=1, max_length=400)
    hypothesis: str = Field(min_length=1, max_length=1000)
    supporting_observation_ids: list[str] = Field(min_length=1, max_length=500)
    missing_evidence: list[str] = Field(max_length=20)
    validation_questions: list[str] = Field(min_length=1, max_length=12)
    manual_review_actions: list[str] = Field(min_length=1, max_length=8)
    prerequisites: list[str] = Field(max_length=8)
    execution_mode: Literal["manual_human_review_only"] = "manual_human_review_only"
    disposition: Literal["requires_independent_validation"] = "requires_independent_validation"


class ValidationStrategyPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    plan_version: Literal["1"] = "1"
    status: Literal["review_required"] = "review_required"
    items: list[ValidationStrategyItem] = Field(max_length=100)
    global_prerequisites: list[str] = Field(min_length=1, max_length=8)
    safety_constraints: Literal[
        "Planning only: no requests, payloads, commands, credentials, state changes, or automated tests are generated or executed."
    ] = "Planning only: no requests, payloads, commands, credentials, state changes, or automated tests are generated or executed."
