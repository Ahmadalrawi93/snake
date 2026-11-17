"""Read schema for persisted AI analysis runs."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class AnalysisRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    created_by: int
    context_sha256: str
    correlations_sha256: str
    provider: str
    model: str
    status: Literal["completed"]
    disposition: Literal["requires_independent_validation"]
    result: dict
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    cost_usd: str | None
    provider_request_id: str | None
    execution_enabled: Literal[False]
    created_at: datetime
