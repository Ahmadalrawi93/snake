"""Conservative finding similarity and duplicate-review contracts."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class CandidateSimilarityInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    candidate_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    category: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=8, max_length=180)
    observation_ids: list[str] = Field(max_length=500)
    evidence_texts: list[str] = Field(default_factory=list, max_length=100)


class CandidateSimilarityResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    candidate_fingerprint: str
    compared_fingerprint: str
    disposition: Literal["exact_duplicate", "possible_duplicate", "distinct"]
    category_match: bool
    category_family_match: bool
    title_similarity: float = Field(ge=0, le=1)
    evidence_similarity: float = Field(ge=0, le=1)
    shared_observation_count: int = Field(ge=0)
    shared_route_count: int = Field(ge=0)
    rationale: list[str] = Field(max_length=8)
    requires_human_review: Literal[True] = True
    auto_merge: Literal[False] = False
