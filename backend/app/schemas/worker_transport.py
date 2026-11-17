"""Bounded, signed worker response contract for mTLS task delivery."""
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.core.worker_signing import SignedWorkerValidationResult
from app.schemas.worker_results import SignedWorkerObservationBatch

class WorkerTaskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    acknowledgement: SignedWorkerValidationResult
    observation_batch: SignedWorkerObservationBatch | None = Field(default=None)

    @model_validator(mode="after")
    def enforce_wire_size(self):
        if len(self.model_dump_json().encode("utf-8")) > 64 * 1024:
            raise ValueError("worker response exceeds 64 KiB transport limit")
        return self
