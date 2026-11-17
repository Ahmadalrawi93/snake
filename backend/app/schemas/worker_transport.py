"""Bounded, signed worker response contract for mTLS task delivery."""
from pydantic import BaseModel, ConfigDict, Field
from app.core.worker_signing import SignedWorkerValidationResult
from app.schemas.worker_results import SignedWorkerObservationBatch

class WorkerTaskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    acknowledgement: SignedWorkerValidationResult
    observation_batch: SignedWorkerObservationBatch | None = Field(default=None)
