from app.core.hypothesis_ranking import rank_hypotheses
from app.schemas.validation_strategy import ValidationStrategyItem, ValidationStrategyPlan

def strategy(sid, category, hypothesis, priority="medium", obs=None):
    return ValidationStrategyItem(strategy_id=sid, category=category, priority=priority,
        priority_basis="Passive observations suggest review", hypothesis=hypothesis,
        supporting_observation_ids=obs or ["obs-1"], missing_evidence=[],
        validation_questions=["Review expected authorization behavior"],
        manual_review_actions=["Review approved test-account records"],
        prerequisites=["Written authorization"])

def plan(items):
    return ValidationStrategyPlan(items=items, global_prerequisites=["Written authorization"])

def test_business_logic_and_high_priority_rank_ahead_of_low_priority():
    report=rank_hypotheses(plan([
        strategy("general_review","general_review","Review configuration", "low"),
        strategy("object_review","object_authorization","Review object ownership", "high", ["a","b"]),
    ]))
    assert report.items[0].strategy_id == "object_review"
    assert report.items[0].rank_score > report.items[1].rank_score

def test_exact_normalized_hypotheses_are_deduplicated():
    report=rank_hypotheses(plan([
        strategy("object_review","object_authorization","A user may access another user's invoice"),
        strategy("object_review_copy","object_authorization","A user may access another user s invoice"),
    ]))
    assert report.duplicate_group_count == 1
    assert len(report.items) == 1
    assert report.items[0].duplicate_count == 1
    assert report.items[0].duplicate_of_strategy_id == "object_review_copy"

def test_same_route_category_but_different_hypotheses_stay_separate():
    report=rank_hypotheses(plan([
        strategy("read_review","object_authorization","A user may read another user's invoice"),
        strategy("delete_review","object_authorization","A user may delete another user's invoice"),
    ]))
    assert len(report.items) == 2
    assert report.duplicate_group_count == 0

def test_deterministic_order_and_no_confidence_claims():
    p=plan([strategy("b_review","workflow_integrity","Could approve an unauthorized transfer"),
            strategy("a_review","authentication_boundary","Could bypass login boundary")])
    first=rank_hypotheses(p).model_dump()
    second=rank_hypotheses(p).model_dump()
    assert first == second
    assert first["execution_enabled"] is False
    assert first["confidence_score"] is None
    assert first["vulnerability_severity"] is None
