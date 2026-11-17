from app.core.hypothesis_ranking import apply_investigation_learning
from app.schemas.hypothesis_ranking import HypothesisRankedItem, HypothesisRankingReport
from app.schemas.investigation_memory import InvestigationMemoryReport

def test_human_false_positive_history_adjusts_priority_without_suppressing():
    report = HypothesisRankingReport(items=[
        HypothesisRankedItem(strategy_id="review-a", category="object_authorization",
            hypothesis_fingerprint="a"*64, rank_score=60, rank=1, duplicate_count=0,
            supporting_observation_count=3, priority_basis="high", ranking_factors=["base"]),
        HypothesisRankedItem(strategy_id="review-b", category="general_review",
            hypothesis_fingerprint="b"*64, rank_score=55, rank=2, duplicate_count=0,
            supporting_observation_count=2, priority_basis="medium", ranking_factors=["base"]),
    ], duplicate_group_count=0)
    memory = InvestigationMemoryReport(
        current_strategy_id="review-a", hypothesis_fingerprint="a"*64, prior_matches=[],
        memory_scope="same_project_and_same_target_only", reviewed_run_count=3,
        confirmed_run_count=0, false_positive_run_count=3, inconclusive_run_count=0,
        duplicate_run_count=0, learning_recommendation="deprioritize_review_priority",
        priority_adjustment=-10,
    )
    adjusted = apply_investigation_learning(report, memory)
    assert adjusted.items[0].strategy_id == "review-b"
    assert adjusted.items[1].strategy_id == "review-a"
    assert adjusted.items[1].rank_score == 50
    assert "human_review_history_priority_adjustment:-10" in adjusted.items[1].ranking_factors
    assert len(adjusted.items) == 2
    assert adjusted.execution_enabled is False
