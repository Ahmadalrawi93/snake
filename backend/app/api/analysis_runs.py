"""Owner-scoped read-only access to immutable AI triage history."""
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import AIAnalysisRun, Project, User
from app.schemas.analysis_runs import AnalysisRunRead

router = APIRouter(prefix="/api/v1")


def _serialize(record: AIAnalysisRun) -> dict:
    return {
        "id": record.id,
        "project_id": record.project_id,
        "target_id": record.target_id,
        "created_by": record.created_by,
        "context_sha256": record.context_sha256,
        "provenance_sha256": record.provenance_sha256,
        "source_observation_count": record.source_observation_count,
        "correlations_sha256": record.correlations_sha256,
        "provider": record.provider,
        "model": record.model,
        "status": record.status,
        "disposition": record.disposition,
        "result": json.loads(record.result_json),
        "prompt_tokens": record.prompt_tokens,
        "completion_tokens": record.completion_tokens,
        "total_tokens": record.total_tokens,
        "cost_usd": record.cost_usd,
        "provider_request_id": record.provider_request_id,
        "execution_enabled": record.execution_enabled,
        "created_at": record.created_at,
    }


@router.get("/projects/{project_id}/analysis-runs", response_model=list[AnalysisRunRead])
def list_analysis_runs(
    project_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    records = (
        db.query(AIAnalysisRun)
        .filter_by(project_id=project_id)
        .order_by(AIAnalysisRun.id.desc())
        .limit(limit)
        .all()
    )
    return [_serialize(record) for record in records]
