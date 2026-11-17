from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=4000)

class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    created_at: datetime

class AuthorizationCreate(BaseModel):
    reference: str = Field(min_length=3, max_length=500)
    starts_at: str | None = None
    expires_at: str | None = None
    notes: str = Field(default="", max_length=4000)

class AuthorizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    reference: str
    starts_at: str | None
    expires_at: str | None
    status: str
    notes: str
    created_at: datetime

class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    target_type: str = Field(default="url", pattern="^(url|domain|ip|cidr)$")

class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    value: str
    target_type: str
    status: str
    created_at: datetime

class AuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    action: str
    resource_type: str
    resource_id: str
    details: str
    created_at: datetime
