"""Conservative finding-candidate qualification; AI cannot confirm vulnerabilities."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class FindingQualification(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    candidate_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    category: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=8, max_length=180)
    qualification: Literal["insufficient_evidence", "human_review_candidate"]
    evidence_quality: Literal["insufficient", "mixed", "documented_consistent"]
    impact_quality: Literal["not_documented", "documented_not_independently_verified"]
    duplicate_of_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    blockers: list[str] = Field(max_length=12)
    evidence_ids: list[str] = Field(max_length=100)
    observation_ids: list[str] = Field(max_length=500)
    disposition: Literal["unconfirmed_candidate_requires_human_decision"] = "unconfirmed_candidate_requires_human_decision"
    finding_status: Literal["unconfirmed"] = "unconfirmed"
    execution_enabled: Literal[False] = False
