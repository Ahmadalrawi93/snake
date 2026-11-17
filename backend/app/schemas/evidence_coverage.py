"""Evidence coverage reporting, explicitly separate from confidence and severity."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class EvidenceCoverageAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    strategy_id: str
    coverage_score: int = Field(ge=0, le=100)
    coverage_band: Literal["low", "partial", "substantial", "complete"]
    documented_elements: list[str] = Field(max_length=10)
    missing_elements: list[str] = Field(max_length=10)
    contradiction_count: int = Field(ge=0)
    evidence_item_count: int = Field(ge=1, le=100)
    distinct_source_labels: int = Field(ge=1, le=100)
    impact_documented: bool
    impact_independently_verified: Literal[False] = False
    confidence_score: Literal[None] = None
    vulnerability_severity: Literal[None] = None
    disposition: Literal["coverage_only_requires_human_interpretation"] = "coverage_only_requires_human_interpretation"
    execution_enabled: Literal[False] = False
