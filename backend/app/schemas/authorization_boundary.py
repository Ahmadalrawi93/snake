"""Authorization-boundary review hypotheses; passive hints only."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class AuthorizationSurface(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    route_template: str = Field(min_length=1, max_length=1024)
    surface_kind: Literal["privileged", "ordinary", "object_reference"]
    markers: list[str] = Field(min_length=1, max_length=12)
    observation_ids: list[str] = Field(min_length=1, max_length=500)

class AuthorizationBoundaryHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253)
    resource: str = Field(min_length=1, max_length=80)
    surfaces: list[AuthorizationSurface] = Field(min_length=2, max_length=30)
    review_reasons: list[Literal["privileged_and_ordinary_surfaces_coexist", "object_reference_surface_observed", "role_or_permission_surface_observed"]]
    validation_questions: list[str] = Field(min_length=1, max_length=10)
    supporting_observation_ids: list[str] = Field(min_length=1, max_length=500)
    disposition: Literal["manual_authorization_boundary_review_only"] = "manual_authorization_boundary_review_only"

class AuthorizationBoundaryReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    report_version: Literal["1"] = "1"
    hypotheses: list[AuthorizationBoundaryHypothesis] = Field(max_length=500)
    execution_enabled: Literal[False] = False
    confirmed: Literal[False] = False
    limitation: Literal["Passive paths do not establish authentication, effective roles, object ownership, or server-side access-control enforcement."] = "Passive paths do not establish authentication, effective roles, object ownership, or server-side access-control enforcement."
