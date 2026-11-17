"""Cross-surface relationships derived only from observed routes."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class CrossSurfaceLink(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253)
    relation: Literal[
        "authentication_to_object_surface",
        "authentication_to_sensitive_action",
        "object_to_sensitive_action",
    ]
    observation_ids: list[str] = Field(min_length=2, max_length=500)
    rationale: str = Field(min_length=1, max_length=500)
    validation_questions: list[str] = Field(min_length=1, max_length=6)
    disposition: Literal["requires_independent_validation"] = "requires_independent_validation"


class CrossSurfaceProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    profile_version: Literal["1"] = "1"
    links: list[CrossSurfaceLink] = Field(max_length=500)
    limitations: Literal[
        "Same-host route co-occurrence does not prove shared authentication, authorization, role boundaries, workflow order, or vulnerability."
    ] = "Same-host route co-occurrence does not prove shared authentication, authorization, role boundaries, workflow order, or vulnerability."
