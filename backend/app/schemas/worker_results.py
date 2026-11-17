"""Strict worker observation contract.

Observations are untrusted recon data, never vulnerability findings. The schema
intentionally excludes commands, scripts, arbitrary URLs to fetch, and severity
or confirmation fields.
"""
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SAFE_VALUE = r"^[^\x00-\x1f\x7f]{1,2048}$"


class WorkerObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    observation_id: UUID
    kind: Literal["hostname", "url", "ip", "technology", "http_header", "dns_record"]
    value: Annotated[str, Field(min_length=1, max_length=2048, pattern=_SAFE_VALUE)]
    evidence: str = Field(default="", max_length=8192)
    source: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    observed_at: datetime

    @model_validator(mode="after")
    def validate_time(self):
        if self.observed_at.tzinfo is None:
            raise ValueError("observation timestamp must be timezone-aware")
        return self


class WorkerObservationBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: UUID
    envelope_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    worker_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._-]+$")
    key_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._-]+$")
    collected_at: datetime
    observations: list[WorkerObservation] = Field(max_length=500)
    execution_enabled: Literal[False] = False

    @model_validator(mode="after")
    def validate_batch(self):
        if self.collected_at.tzinfo is None:
            raise ValueError("batch timestamp must be timezone-aware")
        ids = [item.observation_id for item in self.observations]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate observation_id in batch")
        for item in self.observations:
            if item.observed_at > self.collected_at:
                raise ValueError("observation cannot be later than collection time")
        return self


class SignedWorkerObservationBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    batch: WorkerObservationBatch
    signature: str = Field(pattern=r"^ed25519:v1:[A-Za-z0-9_-]{86}$")
