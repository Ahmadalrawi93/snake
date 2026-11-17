"""Append-only lifecycle and encrypted evidence vault contracts."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

FindingStatus = Literal["new", "under_review", "needs_more_evidence", "confirmed", "rejected", "duplicate"]


class FindingLifecycleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_status: FindingStatus
    new_status: FindingStatus
    rationale: str = Field(min_length=3, max_length=2000)
    related_candidate_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @field_validator("rationale")
    @classmethod
    def safe_rationale(cls, value: str) -> str:
        if any(ord(c) < 32 and c not in "\\t\\n" for c in value) or "\\x7f" in value:
            raise ValueError("control characters are not allowed")
        return value.strip()


class FindingLifecycleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    candidate_id: int
    project_id: int
    actor_id: int
    from_status: str
    to_status: str
    rationale: str
    related_candidate_fingerprint: str | None
    created_at: datetime


class EvidenceArtifactCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    filename: str = Field(min_length=1, max_length=180)
    media_type: Literal["text/plain", "application/json", "image/png", "image/jpeg", "application/pdf", "application/octet-stream"]
    content_base64: str = Field(min_length=4, max_length=1400000)
    description: str = Field(default="", max_length=1000)

    @field_validator("filename", "description")
    @classmethod
    def safe_metadata(cls, value: str) -> str:
        if any(ord(c) < 32 and c not in "\\t\\n" for c in value) or "\\x7f" in value:
            raise ValueError("control characters are not allowed")
        return value.strip()


class EvidenceArtifactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    candidate_id: int
    project_id: int
    uploaded_by: int
    filename: str
    media_type: str
    content_sha256: str
    size_bytes: int
    description: str
    created_at: datetime
