"""Deterministic, non-destructive candidate similarity analysis."""
import re
from urllib.parse import urlsplit

from app.schemas.finding_intelligence import CandidateSimilarityInput, CandidateSimilarityResult


_CATEGORY_FAMILIES = {
    "authorization": {"object_authorization", "authorization", "access_control", "idor", "broken_access_control"},
    "information_exposure": {"information_exposure", "information_disclosure", "data_exposure"},
    "injection": {"injection", "sql_injection", "xss", "command_injection"},
    "authentication": {"authentication", "authn", "account_takeover"},
}


def _tokens(value: str) -> set[str]:
    normalized = value.casefold()
    normalized = re.sub(r"[^a-z0-9_\s-]", " ", normalized)
    return {token for token in re.split(r"[\s_-]+", normalized) if len(token) > 1}


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _category_family(category: str) -> str:
    normalized = category.casefold().strip()
    for family, members in _CATEGORY_FAMILIES.items():
        if normalized in members:
            return family
    return normalized


def _route_signatures(texts: list[str]) -> set[str]:
    """Extract normalized API paths and resource prefixes from evidence text."""
    routes: set[str] = set()
    for text in texts:
        for match in re.findall(r"/(?:api|v[0-9]+|graphql)(?:/[A-Za-z0-9._~:%-]+)*", text, re.I):
            path = match.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"
            path = re.sub(r"/[0-9]+(?=/|$)", "/:id", path)
            path = re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", "/:id", path, flags=re.I)
            segments = path.split("/")
            # Keep the full route and the object/resource prefix before nested actions.
            routes.add(path.casefold())
            for index, segment in enumerate(segments):
                if segment == ":id":
                    routes.add("/".join(segments[:index + 1]).casefold())
                    break
    return routes

def _evidence_tokens(candidate: CandidateSimilarityInput) -> set[str]:
    return _tokens(" ".join(candidate.evidence_texts))


def compare_candidates(
    candidate: CandidateSimilarityInput,
    prior: CandidateSimilarityInput,
) -> CandidateSimilarityResult:
    """Compare root-cause clues without merging, suppressing, or confirming either one."""
    shared = len(set(candidate.observation_ids) & set(prior.observation_ids))
    title_similarity = _jaccard(_tokens(candidate.title), _tokens(prior.title))
    evidence_similarity = _jaccard(_evidence_tokens(candidate), _evidence_tokens(prior))
    left_routes, right_routes = _route_signatures(candidate.evidence_texts), _route_signatures(prior.evidence_texts)
    shared_routes = len(left_routes & right_routes)
    category_match = candidate.category.casefold().strip() == prior.category.casefold().strip()
    family_match = _category_family(candidate.category) == _category_family(prior.category)

    if candidate.candidate_fingerprint == prior.candidate_fingerprint:
        return CandidateSimilarityResult(
            candidate_fingerprint=candidate.candidate_fingerprint,
            compared_fingerprint=prior.candidate_fingerprint,
            disposition="exact_duplicate", category_match=category_match,
            category_family_match=family_match, title_similarity=1.0,
            evidence_similarity=1.0, shared_observation_count=shared,
            shared_route_count=shared_routes,
            rationale=["identical_category_and_hypothesis_fingerprint"],
        )

    rationale: list[str] = []
    if not family_match:
        rationale.append("different_root_cause_families")
        disposition = "distinct"
    else:
        if not category_match:
            rationale.append("same_broad_root_cause_family")
        if title_similarity >= 0.80:
            rationale.append("high_title_token_similarity")
        if evidence_similarity >= 0.72:
            rationale.append("high_evidence_token_similarity")
        elif evidence_similarity >= 0.55:
            rationale.append("meaningful_evidence_token_overlap")
        if shared:
            rationale.append("shared_source_observations")
        if shared_routes:
            rationale.append("shared_normalized_routes")
        # Cross-category comparisons require strong evidence overlap and a shared route.
        cross_family_candidate = (
            not category_match and evidence_similarity >= 0.55 and shared_routes >= 1
        )
        same_category_candidate = (
            category_match and (
                title_similarity >= 0.80
                or evidence_similarity >= 0.72
                or (title_similarity >= 0.55 and (shared >= 2 or (evidence_similarity >= 0.50 and shared_routes >= 1)))
            )
        )
        disposition = "possible_duplicate" if cross_family_candidate or same_category_candidate else "distinct"

    if not rationale:
        rationale.append("insufficient_independent_similarity_signals")
    return CandidateSimilarityResult(
        candidate_fingerprint=candidate.candidate_fingerprint,
        compared_fingerprint=prior.candidate_fingerprint,
        disposition=disposition, category_match=category_match,
        category_family_match=family_match,
        title_similarity=round(title_similarity, 4),
        evidence_similarity=round(evidence_similarity, 4),
        shared_observation_count=shared, shared_route_count=shared_routes,
        rationale=rationale,
    )


def compare_candidate_set(candidate: CandidateSimilarityInput, prior_candidates: list[CandidateSimilarityInput]):
    """Return deterministic comparisons sorted by disposition and fingerprint."""
    results = [compare_candidates(candidate, prior) for prior in prior_candidates]
    rank = {"exact_duplicate": 0, "possible_duplicate": 1, "distinct": 2}
    return sorted(results, key=lambda item: (rank[item.disposition], item.compared_fingerprint))
