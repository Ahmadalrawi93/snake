"""Structured, evidence-linked impact claims and conservative severity suggestions."""
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


ImpactDimension = Literal[
    "confidentiality", "integrity", "availability", "authentication",
    "authorization", "privilege_escalation", "financial", "privacy", "operational",
]
ImpactLevel = Literal["none", "low", "moderate", "high"]
ImpactScope = Literal[
    "single_test_record", "multiple_records", "tenant_wide", "service_wide", "unknown",
]
DataSensitivity = Literal[
    "synthetic_test_data", "low_sensitivity", "sensitive_data", "critical_system", "unknown",
]


class FindingImpactClaim(BaseModel):
    """A human's structured annotation; it is not independent verification."""
    model_config = ConfigDict(extra="forbid", strict=True)

    evidence_id: UUID
    observation_ids: list[UUID] = Field(min_length=1, max_length=100)
    dimension: ImpactDimension
    level: ImpactLevel
    verification: Literal["observed", "potential"]
    scope: ImpactScope
    data_sensitivity: DataSensitivity
    statement: str = Field(min_length=8, max_length=1200)
    human_attested: Literal[True]


class FindingImpactAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    assessment_status: Literal[
        "no_structured_impact_claims",
        "no_impact_demonstrated",
        "potential_impact_only",
        "documented_not_independently_verified",
        "insufficient_or_conflicting_evidence",
    ]
    claims: list[FindingImpactClaim] = Field(max_length=100)
    demonstrated_dimensions: list[ImpactDimension] = Field(max_length=9)
    potential_dimensions: list[ImpactDimension] = Field(max_length=9)
    severity_suggestion: Literal["not_assessed", "low", "medium", "high", "critical"]
    final_severity: Literal["not_assessed"] = "not_assessed"
    cvss_vector: Literal[None] = None
    evidence_references: list[str] = Field(max_length=200)
    blockers: list[str] = Field(max_length=30)
    rationale: list[str] = Field(max_length=30)
    independent_validation_required: Literal[True] = True
    execution_enabled: Literal[False] = False
