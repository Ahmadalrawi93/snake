"""Deterministic candidate qualification; never marks a finding as confirmed."""
import hashlib
import re
from uuid import UUID

from app.schemas.validation_strategy import ValidationStrategyItem
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceAssessment
from app.schemas.finding_qualification import FindingQualification
from app.schemas.evidence_gap_intelligence import EvidenceGapReport


def _fingerprint(category: str, hypothesis: str) -> str:
    normalized = re.sub(r"\s+", " ", hypothesis).strip().casefold()
    canonical = f"{category.strip().casefold()}\n{normalized}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def qualify_finding_candidate(
    strategy: ValidationStrategyItem,
    bundle: ValidationEvidenceBundle,
    assessment: ValidationEvidenceAssessment,
    *,
    prior_candidate_fingerprints: list[str] | None = None,
    evidence_gaps: EvidenceGapReport | None = None,
) -> FindingQualification:
    """Return a review candidate only when evidence is coherent and documented.

    This function does not verify truth, authorization, exploitability, or impact.
    Its output is always unconfirmed and cannot authorize testing.
    """
    if bundle.strategy_id != strategy.strategy_id or assessment.strategy_id != strategy.strategy_id:
        raise ValueError("strategy, evidence bundle, and assessment must match")
    if not re.fullmatch(r"[a-f0-9]{64}", bundle.analysis_context_sha256):
        raise ValueError("invalid analysis context digest")

    # Do not trust detached assessment summaries: bind their counts and IDs
    # back to the exact evidence bundle supplied to this function.
    bundle_evidence_ids = {item.evidence_id for item in bundle.items}
    assessed_evidence_ids = set(assessment.evidence_ids)
    bundle_observation_ids = {
        observation_id for item in bundle.items for observation_id in item.observation_ids
    }
    assessed_observation_ids = set(assessment.observation_ids)
    if assessed_evidence_ids != bundle_evidence_ids:
        raise ValueError("assessment evidence IDs do not match evidence bundle")
    if assessed_observation_ids != bundle_observation_ids:
        raise ValueError("assessment observation IDs do not match evidence bundle")
    expected_counts = {
        "supporting_evidence_count": sum(item.relationship == "supports" for item in bundle.items),
        "contradicting_evidence_count": sum(item.relationship == "contradicts" for item in bundle.items),
        "context_evidence_count": sum(item.relationship == "context_only" for item in bundle.items),
    }
    for field, expected in expected_counts.items():
        if getattr(assessment, field) != expected:
            raise ValueError(f"assessment {field} does not match evidence bundle")

    if evidence_gaps is not None and evidence_gaps.strategy_id != strategy.strategy_id:
        raise ValueError("evidence gap report does not match validation strategy")

    fingerprint = _fingerprint(strategy.category, strategy.hypothesis)
    prior = set(prior_candidate_fingerprints or [])
    if any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in prior):
        raise ValueError("invalid prior candidate fingerprint")

    blockers = list(assessment.required_gaps)
    if evidence_gaps is not None:
        blockers.extend(
            f"evidence_gap:{gap.category}"
            for gap in evidence_gaps.gaps if gap.hard_blocker
        )
    if assessment.evidence_status != "consistent":
        blockers.append("evidence_is_not_consistent")
    if assessment.contradicting_evidence_count:
        blockers.append("contradictory_evidence_requires_resolution")
    if assessment.readiness != "human_review_ready":
        blockers.append("validation_evidence_not_ready_for_human_review")
    if assessment.impact_status != "documented_not_independently_verified":
        blockers.append("impact_context_not_documented")
    if not any(
        item.evidence_type == "observed_behavior" and item.relationship == "supports"
        for item in bundle.items
    ):
        blockers.append("supporting_observed_behavior_missing")

    duplicate_of = fingerprint if fingerprint in prior else None
    if duplicate_of:
        blockers.append("candidate_matches_a_prior_category_and_hypothesis_fingerprint")

    blockers = list(dict.fromkeys(blockers))
    ready = not blockers
    evidence_quality = (
        "mixed" if assessment.evidence_status == "mixed"
        else "documented_consistent" if ready
        else "insufficient"
    )
    return FindingQualification(
        candidate_fingerprint=fingerprint,
        category=strategy.category,
        title=strategy.hypothesis[:180],
        qualification="human_review_candidate" if ready and not duplicate_of else "insufficient_evidence",
        evidence_quality=evidence_quality,
        impact_quality=assessment.impact_status,
        duplicate_of_fingerprint=duplicate_of,
        blockers=blockers,
        evidence_ids=[str(value) for value in assessment.evidence_ids],
        observation_ids=[str(value) for value in assessment.observation_ids],
    )
