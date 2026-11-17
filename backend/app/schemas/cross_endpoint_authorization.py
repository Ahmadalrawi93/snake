"""Cross-endpoint authorization review hypotheses from passive evidence only."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class EndpointOperationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    route_template: str = Field(min_length=1,max_length=1024)
    operation_kind: Literal["collection","object","named_action","bulk","export"]
    action_markers: list[str] = Field(max_length=12)
    object_reference_present: bool
    observation_ids: list[str] = Field(min_length=1,max_length=500)

class CrossEndpointAuthorizationHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid",strict=True)
    host: str = Field(min_length=1,max_length=253)
    resource: str = Field(min_length=1,max_length=80)
    operations: list[EndpointOperationEvidence] = Field(min_length=2,max_length=40)
    review_reasons: list[Literal["operation_surfaces_coexist","object_and_collection_surfaces_coexist","bulk_or_export_surface_observed","multiple_named_actions_observed"]]
    validation_questions: list[str] = Field(min_length=1,max_length=12)
    supporting_observation_ids: list[str] = Field(min_length=1,max_length=500)
    disposition: Literal["manual_cross_endpoint_authorization_review_only"]="manual_cross_endpoint_authorization_review_only"

class CrossEndpointAuthorizationReport(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    report_version: Literal["1"]="1"
    hypotheses: list[CrossEndpointAuthorizationHypothesis]=Field(max_length=500)
    execution_enabled: Literal[False]=False
    confirmed: Literal[False]=False
    limitation: Literal["Passive paths do not establish supported HTTP methods, endpoint reachability, authorization enforcement, or vulnerability impact."]="Passive paths do not establish supported HTTP methods, endpoint reachability, authorization enforcement, or vulnerability impact."
