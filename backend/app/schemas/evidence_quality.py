"""Evidence quality and source-diversity reporting; not truth or confidence."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class EvidenceQualityAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    strategy_id: str
    evidence_item_count: int = Field(ge=1, le=100)
    supporting_count: int = Field(ge=0, le=100)
    contradicting_count: int = Field(ge=0, le=100)
    context_only_count: int = Field(ge=0, le=100)
    distinct_source_labels: int = Field(ge=1, le=100)
    independent_source_count: int = Field(ge=0, le=100)
    repeated_evidence_groups: int = Field(ge=0, le=100)
    observation_overlap_groups: int = Field(ge=0, le=100)
    source_independence: Literal["not_assessed", "single_labeled_source", "multiple_labeled_sources_unverified"]
    quality_band: Literal["limited", "mixed", "documented_diverse"]
    warnings: list[str] = Field(max_length=12)
    source_independence_verified: Literal[False] = False
    confidence_score: Literal[None] = None
    vulnerability_severity: Literal[None] = None
    execution_enabled: Literal[False] = False
    disposition: Literal["documentary_quality_only_requires_human_interpretation"] = "documentary_quality_only_requires_human_interpretation"
