"""Derive deterministic, provenance-bound evidence gaps from human evidence."""
import hashlib

from app.schemas.validation_strategy import ValidationStrategyItem
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceAssessment
from app.schemas.evidence_gap_intelligence import EvidenceGap, EvidenceGapReport


_GAP_DEFINITIONS = (
    ("program_policy", "program_policy", "A current written program policy or authorization record is not documented.",
     "A current program policy or written permission that identifies the permitted asset and testing boundaries.",
     "Obtain the policy or permission from the program's official documentation or owner; do not infer permission from asset discovery.", True),
    ("expected_behavior", "expected_behavior", "The application's documented expected behavior is missing.",
     "A policy, specification, or owner statement describing the expected access or workflow behavior.",
     "Use official documentation or a program-owner clarification; do not probe production behavior to guess the intended rule.", True),
    ("observed_behavior", "observed_behavior", "No supporting, observation-linked behavior is recorded for this hypothesis.",
     "A human-reviewed record of behavior from an explicitly authorized test context, linked to in-scope source observations.",
     "Record only behavior already obtained within explicit written scope and designated test identities; this engine does not generate or execute tests.", True),
    ("authorized_test_account", "authorized_test_account", "No designated test-account evidence is documented.",
     "Confirmation that the identities and test objects were supplied or explicitly approved for this program.",
     "Request designated test identities and objects through the program's approved channel; never use real-user accounts or data.", True),
    ("impact_context", "impact_context", "Impact context is not documented; this does not establish that impact is absent.",
     "A source-linked description of the affected asset, data class, or permitted test-object consequence.",
     "Document impact only from approved test artifacts or program-owner confirmation; do not cause irreversible changes or access real-user data.", True),
    ("source_traceability", "source_traceability", "Evidence items are not linked to source observations.",
     "At least one valid observation reference from the verified analysis context.",
     "Attach the original immutable observation reference; do not create or guess source identifiers.", True),
    ("strategy_linkage", "strategy_linkage", "The recorded evidence does not reference any observation supporting this validation strategy.",
     "At least one evidence observation ID that is also listed by this strategy.",
     "Link existing evidence to the exact supporting observation; do not import observations from another target or scope.", True),
)


def _gap_id(strategy_id: str, category: str, evidence_ids: list[str], observation_ids: list[str]) -> str:
    raw = "|".join((strategy_id, category, ",".join(sorted(evidence_ids)),
                    ",".join(sorted(observation_ids))))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def build_evidence_gap_report(
    strategy: ValidationStrategyItem,
    bundle: ValidationEvidenceBundle,
    assessment: ValidationEvidenceAssessment,
) -> EvidenceGapReport:
    """Build gaps from exact bundle contents; never treats missing data as proof of safety."""
    if not (strategy.strategy_id == bundle.strategy_id == assessment.strategy_id):
        raise ValueError("strategy, bundle, and assessment IDs must match")

    evidence_ids = {str(item.evidence_id) for item in bundle.items}
    observation_ids = {str(value) for item in bundle.items for value in item.observation_ids}
    if set(assessment.evidence_ids) != evidence_ids:
        raise ValueError("assessment evidence IDs do not match evidence bundle")
    if set(assessment.observation_ids) != observation_ids:
        raise ValueError("assessment observation IDs do not match evidence bundle")
    expected_counts = {
        "supporting_evidence_count": sum(item.relationship == "supports" for item in bundle.items),
        "contradicting_evidence_count": sum(item.relationship == "contradicts" for item in bundle.items),
        "context_evidence_count": sum(item.relationship == "context_only" for item in bundle.items),
    }
    for field, expected in expected_counts.items():
        if getattr(assessment, field) != expected:
            raise ValueError(f"assessment {field} does not match evidence bundle")

    strategy_ids = {str(value) for value in strategy.supporting_observation_ids}
    if not strategy_ids:
        raise ValueError("strategy has no supporting observations")

    gaps: list[EvidenceGap] = []
    for category, evidence_type, reason, minimum, guidance, hard_blocker in _GAP_DEFINITIONS:
        matching = [item for item in bundle.items if item.evidence_type == evidence_type]
        adequate = any(
            item.relationship == "supports"
            and (evidence_type not in {"observed_behavior", "impact_context"} or bool(item.observation_ids))
            for item in matching
        )
        if category == "source_traceability":
            adequate = any(item.observation_ids for item in bundle.items)
        elif category == "strategy_linkage":
            adequate = bool(strategy_ids.intersection(observation_ids))
        if adequate:
            continue
        related_items = matching
        related_evidence = sorted(str(item.evidence_id) for item in related_items)
        related_observations = sorted({
            str(value) for item in related_items for value in item.observation_ids
        })
        gaps.append(EvidenceGap(
            gap_id=_gap_id(strategy.strategy_id, category, related_evidence, related_observations),
            category=category,
            reason=reason,
            affected_hypothesis=strategy.hypothesis,
            required_evidence_type=evidence_type,
            minimum_acceptable_evidence=minimum,
            acquisition_guidance=guidance,
            related_evidence_ids=related_evidence,
            related_observation_ids=related_observations,
            hard_blocker=hard_blocker,
            observation_state="documented_but_unverified" if matching else "not_documented",
        ))

    contradictions = [item for item in bundle.items if item.relationship == "contradicts"]
    if contradictions:
        related_evidence = sorted(str(item.evidence_id) for item in contradictions)
        related_observations = sorted({
            str(value) for item in contradictions for value in item.observation_ids
        })
        gaps.append(EvidenceGap(
            gap_id=_gap_id(strategy.strategy_id, "contradiction_resolution",
                           related_evidence, related_observations),
            category="contradiction_resolution",
            reason="One or more evidence items contradict the hypothesis and must be reconciled before qualification.",
            affected_hypothesis=strategy.hypothesis,
            required_evidence_type="contradiction_resolution",
            minimum_acceptable_evidence="A human-reviewed explanation supported by source-linked evidence that resolves or accurately preserves each contradiction.",
            acquisition_guidance="Review the original contradictory records and obtain a documented clarification; do not discard contradictory evidence merely to improve readiness.",
            related_evidence_ids=related_evidence,
            related_observation_ids=related_observations,
            hard_blocker=True,
            observation_state="contradictory",
        ))

    gaps.sort(key=lambda gap: (not gap.hard_blocker, gap.category, gap.gap_id))
    return EvidenceGapReport(
        strategy_id=strategy.strategy_id,
        gaps=gaps,
        gap_count=len(gaps),
        hard_blocker_count=sum(gap.hard_blocker for gap in gaps),
    )
