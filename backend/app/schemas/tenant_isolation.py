"""Passive multi-tenant isolation review hypotheses."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class TenantRouteEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    route_template: str = Field(min_length=1, max_length=1024)
    tenant_context: Literal["explicit_tenant_path", "tenant_resource", "unscoped_resource"]
    tenant_markers: list[str] = Field(max_length=8)
    object_reference_present: bool
    observation_ids: list[str] = Field(min_length=1, max_length=500)

class TenantIsolationHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253)
    resource: str = Field(min_length=1, max_length=80)
    route_evidence: list[TenantRouteEvidence] = Field(min_length=2, max_length=30)
    review_reasons: list[Literal["tenant_and_unscoped_surfaces_coexist", "multiple_tenant_scopes_observed", "tenant_object_reference_observed"]]
    validation_questions: list[str] = Field(min_length=1, max_length=10)
    supporting_observation_ids: list[str] = Field(min_length=1, max_length=500)
    disposition: Literal["manual_cross_tenant_isolation_review_only"] = "manual_cross_tenant_isolation_review_only"

class TenantIsolationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    report_version: Literal["1"] = "1"
    hypotheses: list[TenantIsolationHypothesis] = Field(max_length=500)
    execution_enabled: Literal[False] = False
    confirmed: Literal[False] = False
    limitation: Literal["Passive routes cannot establish tenant identity, data ownership, or effective server-side tenant isolation."] = "Passive routes cannot establish tenant identity, data ownership, or effective server-side tenant isolation."
