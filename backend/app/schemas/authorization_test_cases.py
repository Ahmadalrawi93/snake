"""Manual authorization test plans derived from passive review hypotheses."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class ManualAuthorizationTestCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    case_id: str = Field(min_length=1, max_length=80)
    category: Literal["object_ownership", "role_boundary", "cross_tenant", "bulk_authorization", "export_authorization", "workflow_transition", "cross_endpoint_consistency"]
    host: str = Field(min_length=1, max_length=253)
    resource: str = Field(min_length=1, max_length=80)
    objective: str = Field(min_length=1, max_length=500)
    prerequisites: list[str] = Field(min_length=1, max_length=12)
    manual_steps: list[str] = Field(min_length=2, max_length=12)
    expected_secure_behavior: list[str] = Field(min_length=1, max_length=8)
    evidence_to_record: list[str] = Field(min_length=1, max_length=10)
    supporting_observation_ids: list[str] = Field(min_length=1, max_length=500)
    requires_two_authorized_test_identities: bool = True
    state_change_requires_explicit_program_permission: Literal[True] = True
    disposition: Literal["manual_authorized_validation_plan_only"] = "manual_authorized_validation_plan_only"

class AuthorizationTestCaseReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    report_version: Literal["1"] = "1"
    cases: list[ManualAuthorizationTestCase] = Field(max_length=1000)
    execution_enabled: Literal[False] = False
    requests_generated: Literal[False] = False
    credentials_generated: Literal[False] = False
    confirmed: Literal[False] = False
    limitation: Literal["Plans are review guidance only; they do not establish authorization, endpoint behavior, or vulnerability impact."] = "Plans are review guidance only; they do not establish authorization, endpoint behavior, or vulnerability impact."
