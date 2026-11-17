"""Evidence-bound draft report; never a confirmed or severity-scored finding."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class FindingReportDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    report_version: Literal["1"] = "1"
    candidate_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    title: str = Field(min_length=8, max_length=180)
    vulnerability_category: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=20, max_length=1600)
    affected_surface: list[str] = Field(min_length=1, max_length=30)
    prerequisites: list[str] = Field(min_length=1, max_length=20)
    reproduction_steps: list[str] = Field(min_length=1, max_length=30)
    observed_results: list[str] = Field(min_length=1, max_length=30)
    expected_behavior: list[str] = Field(min_length=1, max_length=20)
    security_impact: str = Field(min_length=20, max_length=2000)
    evidence_references: list[str] = Field(min_length=1, max_length=100)
    unresolved_questions: list[str] = Field(max_length=30)
    severity: Literal["not_assessed"] = "not_assessed"
    cvss_vector: Literal[None] = None
    confirmation_status: Literal["unconfirmed_human_review_draft"] = "unconfirmed_human_review_draft"
    execution_enabled: Literal[False] = False
    generated_from_human_attested_evidence: Literal[True] = True
    requires_human_edit_and_independent_validation: Literal[True] = True


class FindingReportPreview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    report: FindingReportDraft
    markdown: str = Field(min_length=1, max_length=20000)
