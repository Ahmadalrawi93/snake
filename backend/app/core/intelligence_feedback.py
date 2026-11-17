"""Deterministic feedback summaries from human labels only.

No AI-generated or unreviewed hypothesis is treated as a positive or negative label.
"""
import hashlib
import json
import re
from collections import defaultdict

from sqlalchemy.orm import Session

from app.db.models import AIAnalysisEvaluation, AIAnalysisRun, Project, User
from app.schemas.intelligence_feedback import IntelligenceFeedbackProfile


_ID_SEGMENT = re.compile(r"(?i)(?:^|/)(?:[0-9]{2,}|[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)")
_NON_WORD = re.compile(r"[^a-z0-9]+")


def _hypothesis_fingerprint(category: str, hypothesis: str) -> str:
    normalized = hypothesis.lower().strip()
    normalized = _ID_SEGMENT.sub("/:id", normalized)
    normalized = _NON_WORD.sub(" ", normalized)
    normalized = " ".join(normalized.split())[:500]
    canonical = json.dumps(
        {"category": category, "hypothesis": normalized},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_intelligence_feedback_profile(
    db: Session, *, project_id: int, actor: User,
) -> IntelligenceFeedbackProfile:
    project = db.query(Project.id).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise LookupError("project not found")

    rows = (
        db.query(AIAnalysisEvaluation.analysis_run_id, AIAnalysisEvaluation.outcome, AIAnalysisRun.result_json)
        .join(AIAnalysisRun, AIAnalysisRun.id == AIAnalysisEvaluation.analysis_run_id)
        .filter(
            AIAnalysisEvaluation.project_id == project_id,
            AIAnalysisRun.project_id == project_id,
        )
        .order_by(AIAnalysisEvaluation.id.asc())
        .all()
    )
    aggregates = defaultdict(lambda: {
        "category": "other", "reviewed": 0, "confirmed": 0,
        "false_positive": 0, "inconclusive": 0, "duplicate": 0,
    })
    # Collapse multiple reviewers of the same run into one conservative label.
    # A confirmed review wins a conflict; false-positive only counts when no
    # reviewer confirmed it. Unresolved labels never become negative evidence.
    per_run = {}
    for run_id, outcome, result_json in rows:
        try:
            result = json.loads(result_json)
            category = result.get("category", "other")
            hypothesis = result.get("hypothesis", "")
            if not isinstance(category, str) or not isinstance(hypothesis, str) or not hypothesis.strip():
                continue
        except (TypeError, ValueError):
            continue
        fingerprint = _hypothesis_fingerprint(category, hypothesis)
        item = per_run.setdefault(run_id, {"fingerprint": fingerprint, "category": category, "outcomes": set()})
        if item["fingerprint"] == fingerprint:
            item["outcomes"].add(outcome)

    evaluated_runs = 0
    for item in per_run.values():
        fingerprint = item["fingerprint"]
        outcomes = item["outcomes"]
        if "confirmed" in outcomes:
            outcome = "confirmed"
        elif "false_positive" in outcomes:
            outcome = "false_positive"
        elif "inconclusive" in outcomes:
            outcome = "inconclusive"
        else:
            outcome = "duplicate"
        bucket = aggregates[fingerprint]
        bucket["category"] = item["category"]
        bucket["reviewed"] += 1
        bucket[outcome] += 1
        evaluated_runs += 1

    patterns = []
    for fingerprint, counts in aggregates.items():
        resolved = counts["confirmed"] + counts["false_positive"]
        precision = counts["confirmed"] / resolved if resolved else None
        # Conservative rule: only repeated, explicitly human-labelled false positives
        # with no confirmed examples are deprioritized. This never suppresses testing.
        if counts["false_positive"] >= 3 and counts["confirmed"] == 0:
            recommendation = "deprioritize"
        elif resolved == 0 or counts["reviewed"] < 3:
            recommendation = "insufficient_evidence"
        else:
            recommendation = "retain"
        patterns.append({
            "fingerprint": fingerprint,
            **counts,
            "resolved_precision": precision,
            "recommendation": recommendation,
        })
    patterns.sort(key=lambda item: (-item["reviewed"], item["fingerprint"]))
    return IntelligenceFeedbackProfile(
        project_id=project_id,
        evaluated_runs=evaluated_runs,
        patterns=patterns[:2000],
    )
