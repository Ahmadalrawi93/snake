"""Calculate documentary coverage only; never confidence, exploitability, or severity."""
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceAssessment
from app.schemas.evidence_coverage import EvidenceCoverageAssessment

_REQUIRED = {
    "program_policy": ("program_policy", 15),
    "expected_behavior": ("expected_behavior", 15),
    "supporting_observed_behavior": ("supporting_observed_behavior", 25),
    "authorized_test_account": ("authorized_test_account", 10),
    "impact_context": ("impact_context", 20),
    "source_traceability": ("source_traceability", 15),
}


def assess_evidence_coverage(
    bundle: ValidationEvidenceBundle,
    assessment: ValidationEvidenceAssessment,
) -> EvidenceCoverageAssessment:
    """Score presence of documented evidence elements, not truth or severity."""
    if bundle.strategy_id != assessment.strategy_id:
        raise ValueError("bundle and assessment strategy IDs must match")
    expected_evidence_ids = {item.evidence_id for item in bundle.items}
    expected_observation_ids = {
        observation_id for item in bundle.items for observation_id in item.observation_ids
    }
    expected_counts = {
        "supporting_evidence_count": sum(item.relationship == "supports" for item in bundle.items),
        "contradicting_evidence_count": sum(item.relationship == "contradicts" for item in bundle.items),
        "context_evidence_count": sum(item.relationship == "context_only" for item in bundle.items),
    }
    if set(assessment.evidence_ids) != expected_evidence_ids:
        raise ValueError("assessment evidence IDs do not match evidence bundle")
    if set(assessment.observation_ids) != expected_observation_ids:
        raise ValueError("assessment observation IDs do not match evidence bundle")
    for field, expected in expected_counts.items():
        if getattr(assessment, field) != expected:
            raise ValueError(f"assessment {field} does not match evidence bundle")
    types = {item.evidence_type for item in bundle.items}
    present = set()
    if "program_policy" in types:
        present.add("program_policy")
    if "expected_behavior" in types:
        present.add("expected_behavior")
    if any(item.evidence_type == "observed_behavior" and item.relationship == "supports"
           and item.observation_ids for item in bundle.items):
        present.add("supporting_observed_behavior")
    if "authorized_test_account" in types:
        present.add("authorized_test_account")
    if any(item.evidence_type == "impact_context" and item.observation_ids
           for item in bundle.items):
        present.add("impact_context")
    if any(item.observation_ids for item in bundle.items):
        present.add("source_traceability")

    score = sum(weight for key, (_, weight) in _REQUIRED.items() if key in present)
    missing = [label for key, (label, _) in _REQUIRED.items() if key not in present]
    band = "low" if score < 30 else "partial" if score < 60 else "substantial" if score < 100 else "complete"
    return EvidenceCoverageAssessment(
        strategy_id=bundle.strategy_id,
        coverage_score=score,
        coverage_band=band,
        documented_elements=sorted(present),
        missing_elements=missing,
        contradiction_count=expected_counts["contradicting_evidence_count"],
        evidence_item_count=len(bundle.items),
        distinct_source_labels=len({item.source_label.casefold() for item in bundle.items}),
        impact_documented="impact_context" in present,
    )
