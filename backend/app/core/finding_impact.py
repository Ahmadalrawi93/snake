"""Deterministic impact assessment bound to human-attested evidence.

The engine never infers impact from free text, never treats potential impact as
observed, and never assigns final severity or CVSS.
"""
from app.schemas.finding_impact import FindingImpactAssessment, FindingImpactClaim
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceAssessment


def _severity_for_claim(claim: FindingImpactClaim) -> str | None:
    """Return a conservative triage suggestion only for sufficiently scoped claims."""
    if claim.verification != "observed" or claim.level == "none":
        return None
    if claim.scope == "unknown" or claim.data_sensitivity == "unknown":
        return None

    if (
        claim.level == "high"
        and claim.scope == "service_wide"
        and claim.data_sensitivity == "critical_system"
    ):
        return "critical"
    if claim.level == "high" and (
        claim.scope in {"tenant_wide", "multiple_records"}
        or claim.dimension == "privilege_escalation"
        or claim.data_sensitivity == "sensitive_data"
    ):
        return "high"
    if claim.level == "high" or (
        claim.level == "moderate"
        and claim.scope in {"multiple_records", "tenant_wide", "service_wide"}
    ):
        return "medium"
    if claim.level in {"low", "moderate"}:
        return "low"
    return None


def assess_finding_impact(
    qualification: FindingQualification,
    bundle: ValidationEvidenceBundle,
    assessment: ValidationEvidenceAssessment,
    claims: list[FindingImpactClaim] | None = None,
) -> FindingImpactAssessment:
    """Assess only structured claims linked to supporting impact evidence.

    Claims are human annotations, not facts independently verified by SNAKE.
    """
    claims = claims or []
    if qualification.qualification != "human_review_candidate":
        raise ValueError("impact assessment requires a human-review candidate")
    if qualification.finding_status != "unconfirmed" or qualification.execution_enabled:
        raise ValueError("candidate must remain unconfirmed and non-executable")
    if bundle.strategy_id != assessment.strategy_id:
        raise ValueError("evidence bundle and assessment strategy do not match")
    if qualification.impact_quality != assessment.impact_status:
        raise ValueError("qualification impact status does not match evidence assessment")
    if bundle.analysis_context_sha256 == "" or assessment.evidence_status not in {"consistent", "mixed", "insufficient"}:
        raise ValueError("invalid evidence assessment")
    evidence_ids = {str(item.evidence_id) for item in bundle.items}
    observation_ids = {str(value) for item in bundle.items for value in item.observation_ids}
    if set(qualification.evidence_ids) != evidence_ids:
        raise ValueError("qualification evidence IDs do not match evidence bundle")
    if set(qualification.observation_ids) != observation_ids:
        raise ValueError("qualification observation IDs do not match evidence bundle")
    if {str(value) for value in assessment.evidence_ids} != evidence_ids:
        raise ValueError("assessment evidence IDs do not match evidence bundle")
    if {str(value) for value in assessment.observation_ids} != observation_ids:
        raise ValueError("assessment observation IDs do not match evidence bundle")

    impact_evidence = {
        str(item.evidence_id): item
        for item in bundle.items
        if item.evidence_type == "impact_context" and item.relationship == "supports"
    }
    seen: set[tuple[str, str]] = set()
    blockers: list[str] = []
    rationale: list[str] = []
    accepted: list[FindingImpactClaim] = []
    for claim in claims:
        key = (str(claim.evidence_id), claim.dimension)
        if key in seen:
            raise ValueError("duplicate impact claim for evidence and dimension")
        seen.add(key)
        source = impact_evidence.get(str(claim.evidence_id))
        if source is None:
            raise ValueError("impact claim must reference supporting impact_context evidence")
        linked = {str(value) for value in source.observation_ids}
        referenced = {str(value) for value in claim.observation_ids}
        if not referenced or not referenced.issubset(linked):
            raise ValueError("impact claim observations must be linked to its evidence item")
        accepted.append(claim)

    if assessment.evidence_status != "consistent":
        blockers.append("evidence_is_not_consistent")
    if not impact_evidence:
        blockers.append("supporting_impact_context_evidence_missing")
    if not accepted:
        blockers.append("structured_human_impact_claims_missing")

    demonstrated = sorted({
        claim.dimension for claim in accepted
        if claim.verification == "observed" and claim.level != "none"
    })
    potential = sorted({
        claim.dimension for claim in accepted
        if claim.verification == "potential" and claim.level != "none"
    })
    if any(
        claim.verification == "observed"
        and (claim.scope == "unknown" or claim.data_sensitivity == "unknown")
        for claim in accepted
    ):
        blockers.append("observed_impact_scope_or_asset_sensitivity_unknown")

    eligible = [
        _severity_for_claim(claim) for claim in accepted
        if assessment.evidence_status == "consistent"
    ]
    eligible = [value for value in eligible if value is not None]
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    severity = max(eligible, key=lambda value: order[value]) if eligible else "not_assessed"

    if assessment.evidence_status != "consistent":
        status = "insufficient_or_conflicting_evidence"
        severity = "not_assessed"
    elif any(claim.verification == "observed" and claim.level != "none" for claim in accepted):
        status = "documented_not_independently_verified"
        rationale.append("Observed impact is based on human-attested annotations, not independent reproduction.")
    elif any(claim.verification == "potential" and claim.level != "none" for claim in accepted):
        status = "potential_impact_only"
        severity = "not_assessed"
        rationale.append("Potential impact is not treated as demonstrated impact.")
    elif not accepted:
        status = "no_structured_impact_claims"
        severity = "not_assessed"
    elif all(claim.level == "none" for claim in accepted):
        status = "no_impact_demonstrated"
        severity = "not_assessed"
        rationale.append("The structured claims explicitly record no security impact.")
    else:
        status = "potential_impact_only"
        severity = "not_assessed"

    if severity != "not_assessed":
        rationale.append("Severity suggestion is a triage aid derived from structured scope and sensitivity annotations.")
        rationale.append("Final severity and CVSS remain unassessed pending independent human validation.")
    if not accepted:
        rationale.append("No structured impact claims were supplied; free-text impact was not interpreted.")
    refs = sorted({f"evidence:{claim.evidence_id}" for claim in accepted})
    refs += sorted({f"observation:{value}" for claim in accepted for value in claim.observation_ids})
    return FindingImpactAssessment(
        assessment_status=status,
        claims=accepted,
        demonstrated_dimensions=demonstrated,
        potential_dimensions=potential,
        severity_suggestion=severity,
        evidence_references=refs,
        blockers=list(dict.fromkeys(blockers)),
        rationale=rationale,
    )
