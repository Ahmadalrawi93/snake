"""Evidence-linked business workflow candidates; never confirmed vulnerabilities."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class BusinessObjectSurface(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253)
    resource: str = Field(min_length=1, max_length=80)
    collection_route: str = Field(min_length=1, max_length=1024)
    object_route: str | None = Field(default=None, max_length=1024)
    observation_ids: list[str] = Field(min_length=1, max_length=500)

class BusinessActionSurface(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253)
    action: Literal["create", "read", "update", "delete", "approve", "cancel", "export", "transfer", "pay", "unknown"]
    route_template: str = Field(min_length=1, max_length=1024)
    related_resource: str | None = Field(default=None, max_length=80)
    observation_ids: list[str] = Field(min_length=1, max_length=500)

class BusinessLogicHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    category: Literal["object_authorization", "role_boundary", "workflow_transition", "sensitive_action"]
    statement: str = Field(min_length=1, max_length=500)
    validation_questions: list[str] = Field(min_length=1, max_length=8)
    supporting_observation_ids: list[str] = Field(min_length=1, max_length=500)
    disposition: Literal["requires_independent_validation"] = "requires_independent_validation"

class BusinessLogicProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    profile_version: Literal["1"] = "1"
    object_surfaces: list[BusinessObjectSurface] = Field(max_length=500)
    action_surfaces: list[BusinessActionSurface] = Field(max_length=500)
    hypotheses: list[BusinessLogicHypothesis] = Field(max_length=500)
    limitations: Literal["Route names and path shapes do not establish HTTP methods, workflow order, object ownership, roles, authorization behavior, or vulnerabilities."] = "Route names and path shapes do not establish HTTP methods, workflow order, object ownership, roles, authorization behavior, or vulnerabilities."
