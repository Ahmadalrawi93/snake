"""Evidence-gap contracts; gaps are documentary requirements, not vulnerability conclusions."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class EvidenceGap(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    gap_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    category: Literal[
        "program_policy", "expected_behavior", "observed_behavior",
        "authorized_test_account", "impact_context", "source_traceability",
        "strategy_linkage", "contradiction_resolution"
    ]
    reason: str = Field(min_length=1, max_length=500)
    affected_hypothesis: str = Field(min_length=1, max_length=1000)
    required_evidence_type: str = Field(min_length=1, max_length=80)
    minimum_acceptable_evidence: str = Field(min_length=1, max_length=500)
    acquisition_guidance: str = Field(min_length=1, max_length=500)
    related_evidence_ids: list[str] = Field(max_length=100)
    related_observation_ids: list[str] = Field(max_length=500)
    hard_blocker: bool
    observation_state: Literal[
        "not_documented", "contradictory", "documented_but_unverified"
    ]


class EvidenceGapReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    strategy_id: str
    gaps: list[EvidenceGap] = Field(max_length=20)
    gap_count: int = Field(ge=0, le=20)
    hard_blocker_count: int = Field(ge=0, le=20)
    evidence_absence_interpretation: Literal[
        "missing_evidence_is_not_evidence_of_absence"
    ] = "missing_evidence_is_not_evidence_of_absence"
    disposition: Literal["manual_evidence_collection_guidance_only"] = "manual_evidence_collection_guidance_only"
    execution_enabled: Literal[False] = False
