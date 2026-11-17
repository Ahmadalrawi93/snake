"""Bounded, evidence-linked correlation output."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class EvidenceLink(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    observation_ids: list[str] = Field(min_length=2, max_length=100)
    relation: Literal[
        "same_host", "same_route_family", "authentication_surface",
        "potential_object_access_surface"
    ]
    rationale: str = Field(min_length=1, max_length=500)


class CorrelationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    input_observation_count: int = Field(ge=0, le=5000)
    links: list[EvidenceLink] = Field(max_length=1000)
    uncorrelated_observation_ids: list[str] = Field(max_length=5000)
    analysis_notice: Literal[
        "Correlations are investigative leads, not vulnerabilities or proof of impact."
    ] = "Correlations are investigative leads, not vulnerabilities or proof of impact."
