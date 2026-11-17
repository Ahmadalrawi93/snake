import pytest
from app.core.finding_intelligence import compare_candidates, compare_candidate_set
from app.schemas.finding_intelligence import CandidateSimilarityInput


def candidate(fp, category, title, observations=(), evidence=()):
    return CandidateSimilarityInput(
        candidate_fingerprint=fp * 64, category=category, title=title,
        observation_ids=list(observations), evidence_texts=list(evidence),
    )


def test_identical_fingerprint_is_exact_duplicate():
    left = candidate("a", "object_authorization", "Cross account invoice access", ["o1"])
    result = compare_candidates(left, left)
    assert result.disposition == "exact_duplicate"
    assert result.auto_merge is False
    assert result.requires_human_review is True


def test_similar_title_and_category_is_only_possible_duplicate():
    left = candidate("a", "object_authorization", "User can access another account invoice", ["o1"])
    right = candidate("b", "object_authorization", "User can access another account invoice record", ["o9"])
    assert compare_candidates(left, right).disposition == "possible_duplicate"


def test_different_root_cause_families_are_not_grouped():
    left = candidate("a", "information_exposure", "Sensitive invoice data exposed", ["o1"])
    right = candidate("b", "object_authorization", "Sensitive invoice data exposed", ["o1"])
    result = compare_candidates(left, right)
    assert result.disposition == "distinct"
    assert "different_root_cause_families" in result.rationale


def test_shared_observations_alone_do_not_make_duplicates():
    left = candidate("a", "object_authorization", "Invoice ownership bypass", ["o1", "o2"])
    right = candidate("b", "object_authorization", "Password reset token leakage", ["o1", "o2"])
    assert compare_candidates(left, right).disposition == "distinct"


def test_evidence_overlap_and_same_route_can_link_different_categories_in_same_family():
    left = candidate("a", "object_authorization", "Cross tenant invoice read", ["o1"],
        ["GET /api/v1/invoices/123 returned another tenant invoice; object ownership check missing"])
    right = candidate("b", "authorization", "Invoice access control failure", ["o9"],
        ["GET /api/v1/invoices/456 returned another tenant invoice; ownership validation absent"])
    result = compare_candidates(left, right)
    assert result.disposition == "possible_duplicate"
    assert result.category_match is False
    assert result.category_family_match is True
    assert result.shared_route_count >= 1
    assert "high_evidence_token_similarity" in result.rationale


def test_same_endpoint_but_different_root_cause_evidence_is_not_duplicate():
    left = candidate("a", "object_authorization", "Invoice ownership bypass", ["o1"],
        ["GET /api/v1/invoices/123 returned another tenant invoice due missing owner check"])
    right = candidate("b", "object_authorization", "Invoice export workflow abuse", ["o2"],
        ["POST /api/v1/invoices/123/export allowed export because workflow approval state was skipped"])
    result = compare_candidates(left, right)
    assert result.shared_route_count == 1
    assert result.disposition == "distinct"


def test_comparison_order_is_stable():
    left = candidate("a", "object_authorization", "User invoice access issue")
    p1 = candidate("c", "object_authorization", "Different thing entirely")
    p2 = candidate("b", "object_authorization", "User invoice access issue")
    results = compare_candidate_set(left, [p1, p2])
    assert results[0].compared_fingerprint == p2.candidate_fingerprint
    assert results[0].disposition == "possible_duplicate"


def test_invalid_fingerprint_is_rejected():
    with pytest.raises(ValueError):
        CandidateSimilarityInput(
            candidate_fingerprint="bad", category="other", title="Long enough title",
            observation_ids=[],
        )
