from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.scope_policy import ScopePolicy

router = APIRouter(prefix="/api/v1")


class ScopeCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class ScopeCheckResponse(BaseModel):
    allowed: bool
    hostname: str | None
    reason: str


@router.post("/scopes/check", response_model=ScopeCheckResponse)
def check_scope(payload: ScopeCheckRequest) -> ScopeCheckResponse:
    policy = ScopePolicy(get_settings().scope_allowlist_items)
    decision = policy.check_url(payload.url)
    return ScopeCheckResponse(
        allowed=decision.allowed,
        hostname=decision.hostname,
        reason=decision.reason,
    )
