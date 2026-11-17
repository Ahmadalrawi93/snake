"""API contracts for immutable, human-attested impact assessment records."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.finding_impact import FindingImpactClaim, FindingImpactAssessment


class FindingImpactAssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    claims: list[FindingImpactClaim] = Field(max_length=100)


class FindingImpactAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    candidate_id: int
    analysis_run_id: int
    project_id: int
    reviewer_id: int
    evidence_bundle_sha256: str
    claims_sha256: str
    assessment_sha256: str
    assessment: FindingImpactAssessment
    final_severity: Literal["not_assessed"]
    cvss_vector: Literal[None]
    execution_enabled: Literal[False]
    created_at: datetime
