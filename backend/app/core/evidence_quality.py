"""Conservative deterministic quality metrics over human-attested evidence records."""
from collections import defaultdict
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceAssessment
from app.schemas.evidence_quality import EvidenceQualityAssessment

def assess_evidence_quality(bundle: ValidationEvidenceBundle, assessment: ValidationEvidenceAssessment) -> EvidenceQualityAssessment:
    if bundle.strategy_id != assessment.strategy_id:
        raise ValueError("bundle and assessment strategy IDs must match")
    ids = {item.evidence_id for item in bundle.items}
    observations = {ref for item in bundle.items for ref in item.observation_ids}
    counts = {
        "supporting_evidence_count": sum(item.relationship == "supports" for item in bundle.items),
        "contradicting_evidence_count": sum(item.relationship == "contradicts" for item in bundle.items),
        "context_evidence_count": sum(item.relationship == "context_only" for item in bundle.items),
    }
    if set(assessment.evidence_ids) != ids or set(assessment.observation_ids) != observations:
        raise ValueError("assessment references do not match evidence bundle")
    for field, expected in counts.items():
        if getattr(assessment, field) != expected:
            raise ValueError(f"assessment {field} does not match evidence bundle")

    sources = defaultdict(list)
    signatures = defaultdict(list)
    observation_sets = defaultdict(list)
    for item in bundle.items:
        sources[item.source_label.strip().casefold()].append(item)
        signature = (item.evidence_type, item.relationship, item.statement.strip().casefold(),
                     tuple(sorted(str(ref) for ref in item.observation_ids)))
        signatures[signature].append(item)
        if item.observation_ids:
            observation_sets[tuple(sorted(str(ref) for ref in item.observation_ids))].append(item)

    repeated = sum(1 for group in signatures.values() if len(group) > 1)
    overlaps = sum(1 for group in observation_sets.values() if len(group) > 1)
    distinct_sources = len(sources)
    supporting_sources = {
        item.source_label.strip().casefold() for item in bundle.items
        if item.relationship == "supports"
    }
    # Labels are caller-supplied metadata, not authenticated source identities.
    independent_count = len(supporting_sources)
    warnings = []
    if distinct_sources == 1:
        warnings.append("all_records_share_one_source_label")
    if repeated:
        warnings.append("duplicate_or_near_duplicate_evidence_records_detected")
    if overlaps:
        warnings.append("multiple_records_reuse_the_same_observation_references")
    if counts["contradicting_evidence_count"]:
        warnings.append("contradictory_evidence_requires_human_resolution")
    if not any(item.relationship == "supports" for item in bundle.items):
        warnings.append("no_supporting_evidence_records")
    band = ("limited" if independent_count <= 1 or repeated or counts["contradicting_evidence_count"]
            else "mixed" if overlaps or counts["context_evidence_count"]
            else "documented_diverse")
    independence = ("not_assessed" if independent_count == 0 else
                    "single_labeled_source" if independent_count == 1 else
                    "multiple_labeled_sources_unverified")
    return EvidenceQualityAssessment(
        strategy_id=bundle.strategy_id, evidence_item_count=len(bundle.items),
        supporting_count=counts["supporting_evidence_count"],
        contradicting_count=counts["contradicting_evidence_count"],
        context_only_count=counts["context_evidence_count"],
        distinct_source_labels=distinct_sources, independent_source_count=independent_count,
        repeated_evidence_groups=repeated, observation_overlap_groups=overlaps,
        source_independence=independence, quality_band=band, warnings=warnings,
    )
