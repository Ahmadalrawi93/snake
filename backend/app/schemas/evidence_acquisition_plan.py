"""Manual evidence acquisition plan contracts; never executable testing instructions."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class EvidenceAcquisitionStep(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    step_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    gap_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    category: str = Field(min_length=1, max_length=80)
    priority: Literal["critical", "high", "normal"]
    action_kind: Literal[
        "retrieve_existing_record", "request_official_clarification",
        "request_designated_test_context", "review_existing_evidence",
        "reconcile_contradictory_records"
    ]
    objective: str = Field(min_length=1, max_length=500)
    acceptable_sources: list[str] = Field(min_length=1, max_length=8)
    prerequisites: list[str] = Field(max_length=10)
    depends_on_step_ids: list[str] = Field(max_length=20)
    safe_boundary: str = Field(min_length=1, max_length=500)
    manual_only: Literal[True] = True


class EvidenceAcquisitionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    strategy_id: str
    plan_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    steps: list[EvidenceAcquisitionStep] = Field(max_length=20)
    step_count: int = Field(ge=0, le=20)
    unresolved_hard_blocker_count: int = Field(ge=0, le=20)
    execution_enabled: Literal[False] = False
    disposition: Literal["human_coordinated_evidence_collection_only"] = "human_coordinated_evidence_collection_only"
