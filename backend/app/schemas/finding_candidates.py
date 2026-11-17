from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import ValidationEvidenceBundle

class FindingCandidateCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    qualification: FindingQualification
    evidence_bundle: ValidationEvidenceBundle

class FindingCandidateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    analysis_run_id: int
    project_id: int
    created_by: int
    candidate_fingerprint: str
    qualification: str
    finding_status: str
    evidence_bundle_sha256: str
    execution_enabled: bool
    created_at: datetime
