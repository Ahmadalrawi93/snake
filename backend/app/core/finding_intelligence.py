"""Deterministic, non-destructive candidate similarity analysis."""
import re
from app.schemas.finding_intelligence import CandidateSimilarityInput, CandidateSimilarityResult


def _tokens(value: str) -> set[str]:
    normalized = value.casefold()
    normalized = re.sub(r"[^a-z0-9_\s-]", " ", normalized)
    return {token for token in re.split(r"[\s_-]+", normalized) if len(token) > 1}


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def compare_candidates(
    candidate: CandidateSimilarityInput,
    prior: CandidateSimilarityInput,
) -> CandidateSimilarityResult:
    """Compare candidates without merging, suppressing, or confirming either one."""
    if candidate.candidate_fingerprint == prior.candidate_fingerprint:
        return CandidateSimilarityResult(
            candidate_fingerprint=candidate.candidate_fingerprint,
            compared_fingerprint=prior.candidate_fingerprint,
            disposition="exact_duplicate", category_match=candidate.category == prior.category,
            title_similarity=1.0, shared_observation_count=len(
                set(candidate.observation_ids) & set(prior.observation_ids)
            ), rationale=["identical_category_and_hypothesis_fingerprint"],
        )

    category_match = candidate.category.casefold().strip() == prior.category.casefold().strip()
    title_similarity = _jaccard(_tokens(candidate.title), _tokens(prior.title))
    shared = len(set(candidate.observation_ids) & set(prior.observation_ids))
    rationale = []
    if not category_match:
        rationale.append("different_categories_are_not_auto_grouped")
        disposition = "distinct"
    else:
        if title_similarity >= 0.80:
            rationale.append("high_title_token_similarity")
        if shared:
            rationale.append("shared_source_observations")
        # Similarity alone never triggers merging. Shared observations strengthen
        # a title match; unrelated observations need a very high title match.
        if title_similarity >= 0.80 or (title_similarity >= 0.55 and shared >= 2):
            disposition = "possible_duplicate"
        else:
            disposition = "distinct"
    if not rationale:
        rationale.append("insufficient_independent_similarity_signals")
    return CandidateSimilarityResult(
        candidate_fingerprint=candidate.candidate_fingerprint,
        compared_fingerprint=prior.candidate_fingerprint,
        disposition=disposition, category_match=category_match,
        title_similarity=round(title_similarity, 4),
        shared_observation_count=shared, rationale=rationale,
    )


def compare_candidate_set(candidate: CandidateSimilarityInput, prior_candidates: list[CandidateSimilarityInput]):
    """Return deterministic comparisons sorted by disposition and fingerprint."""
    results = [compare_candidates(candidate, prior) for prior in prior_candidates]
    rank = {"exact_duplicate": 0, "possible_duplicate": 1, "distinct": 2}
    return sorted(results, key=lambda item: (rank[item.disposition], item.compared_fingerprint))
