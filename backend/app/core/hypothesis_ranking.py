"""Rank AI-generated hypotheses using bounded deterministic metadata only."""
import hashlib
import re
from collections import defaultdict
from app.schemas.validation_strategy import ValidationStrategyPlan
from app.schemas.hypothesis_ranking import HypothesisRankedItem, HypothesisRankingReport

def _normalized(text: str) -> str:
    value = text.casefold()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())

def _fingerprint(category: str, hypothesis: str) -> str:
    raw = category + "\\0" + _normalized(hypothesis)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def rank_hypotheses(plan: ValidationStrategyPlan) -> HypothesisRankingReport:
    """Priority is a review queue hint, never vulnerability likelihood."""
    grouped = defaultdict(list)
    for item in plan.items:
        fp = _fingerprint(item.category, item.hypothesis)
        grouped[fp].append(item)
    representatives = []
    duplicate_groups = 0
    for fp, group in grouped.items():
        ordered = sorted(group, key=lambda x: x.strategy_id)
        representative = ordered[0]
        if len(ordered) > 1:
            duplicate_groups += 1
        representatives.append((fp, representative, len(ordered), ordered[1].strategy_id if len(ordered)>1 else None))
    ranked = []
    for fp, item, duplicate_count, duplicate_of in representatives:
        score = {"high": 30, "medium": 20, "low": 10}[item.priority]
        factors = ["strategy_priority:" + item.priority]
        obs_count = len(set(item.supporting_observation_ids))
        score += min(obs_count, 10) * 3
        if obs_count:
            factors.append("distinct_supporting_observation_references:" + str(obs_count))
        else:
            factors.append("no_supporting_observation_references")
        score += min(len(item.prerequisites), 4) * 2
        if item.category in {"object_authorization", "sensitive_action_authorization", "workflow_integrity", "authentication_boundary"}:
            score += 8
            factors.append("security_boundary_or_business_logic_review_surface")
        score = min(score, 100)
        representatives_item = (score, item.strategy_id, fp, item, duplicate_count, duplicate_of, obs_count, factors)
        ranked.append(representatives_item)
    ranked.sort(key=lambda x: (-x[0], x[1], x[2]))
    result = []
    for index, (score, _sid, fp, item, count, duplicate_of, obs_count, factors) in enumerate(ranked, 1):
        result.append(HypothesisRankedItem(
            strategy_id=item.strategy_id, category=item.category, hypothesis_fingerprint=fp,
            rank_score=score, rank=index, duplicate_of_strategy_id=duplicate_of,
            duplicate_count=count-1, supporting_observation_count=obs_count,
            priority_basis=item.priority_basis, ranking_factors=factors,
        ))
    return HypothesisRankingReport(items=result, duplicate_group_count=duplicate_groups)
