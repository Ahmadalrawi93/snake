"""Compare current strategy evidence references with sibling hypotheses in the same run."""
from app.schemas.validation_strategy import ValidationStrategyPlan
from app.schemas.validation_evidence import ValidationEvidenceBundle
from app.schemas.cross_hypothesis_evidence_reuse import CrossHypothesisEvidenceReuseReport, EvidenceReuseItem

def build_evidence_reuse_report(plan: ValidationStrategyPlan, bundle: ValidationEvidenceBundle) -> CrossHypothesisEvidenceReuseReport:
    if bundle.strategy_id not in {item.strategy_id for item in plan.items}:
        raise ValueError("evidence bundle strategy is not present in the validation plan")
    current = {str(ref) for item in bundle.items for ref in item.observation_ids}
    results = []
    reused = set()
    for strategy in sorted(plan.items, key=lambda item: item.strategy_id):
        if strategy.strategy_id == bundle.strategy_id:
            continue
        sibling = set(strategy.supporting_observation_ids)
        shared = sorted(current & sibling)
        if not shared:
            continue
        reused.update(shared)
        ratio = round((len(shared) / max(1, len(current))) * 100)
        interpretation = "complete_reuse" if current and len(shared) == len(current) else "partial_reuse"
        results.append(EvidenceReuseItem(
            strategy_id=strategy.strategy_id, shared_observation_count=len(shared),
            shared_observation_ids=shared, reuse_ratio_percent=ratio,
            interpretation=interpretation,
        ))
    return CrossHypothesisEvidenceReuseReport(
        current_strategy_id=bundle.strategy_id, current_observation_count=len(current),
        reused_with_other_hypotheses=results, unique_observation_count=len(current - reused),
        memory_status="current_analysis_run_only_no_persistent_history",
    )
