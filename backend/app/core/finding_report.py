"""Build conservative report drafts solely from a human-attested evidence bundle."""
from app.schemas.finding_report import FindingReportDraft
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceAssessment

def build_finding_report_draft(
    qualification: FindingQualification,
    bundle: ValidationEvidenceBundle,
    assessment: ValidationEvidenceAssessment,
) -> FindingReportDraft:
    if qualification.qualification != "human_review_candidate":
        raise ValueError("report draft requires a human-review candidate")
    if qualification.finding_status != "unconfirmed" or qualification.execution_enabled:
        raise ValueError("candidate must remain unconfirmed and non-executable")
    if qualification.candidate_fingerprint == "" or bundle.strategy_id != assessment.strategy_id:
        raise ValueError("candidate and evidence assessment do not match")
    evidence_ids={str(item.evidence_id) for item in bundle.items}
    observation_ids={str(ref) for item in bundle.items for ref in item.observation_ids}
    if set(qualification.evidence_ids) != evidence_ids:
        raise ValueError("qualification evidence IDs do not match evidence bundle")
    if set(qualification.observation_ids) != observation_ids:
        raise ValueError("qualification observation IDs do not match evidence bundle")
    if assessment.evidence_status != "consistent" or assessment.readiness != "human_review_ready":
        raise ValueError("inconsistent or incomplete evidence cannot produce a report draft")
    supporting=[item for item in bundle.items if item.relationship=="supports"]
    observed=[item for item in supporting if item.evidence_type=="observed_behavior"]
    expected=[item for item in bundle.items if item.evidence_type=="expected_behavior"]
    impacts=[item for item in bundle.items if item.evidence_type=="impact_context"]
    if not observed:
        raise ValueError("supporting observed behavior is required")
    if not expected:
        raise ValueError("documented expected behavior is required")
    if not impacts:
        raise ValueError("documented impact context is required")
    refs=sorted({str(item.evidence_id) for item in bundle.items})
    obs_refs=sorted(observation_ids)
    prerequisites=[
        item.statement for item in bundle.items
        if item.evidence_type=="authorized_test_account" and item.relationship=="supports"
    ]
    if not prerequisites:
        prerequisites=["Use only program-designated test accounts and records explicitly authorized for this test."]
    return FindingReportDraft(
        candidate_fingerprint=qualification.candidate_fingerprint,
        title=qualification.title,
        vulnerability_category=qualification.category,
        summary=(
            "This is an unconfirmed report draft based on human-attested evidence. "
            "It describes the documented behavior and impact context below; it does not independently "
            "verify exploitability, authorization, or the vulnerability claim."
        ),
        affected_surface=sorted({item.source_label for item in bundle.items}),
        prerequisites=prerequisites[:20],
        reproduction_steps=[
            "Confirm the program policy and exact affected surface are in scope.",
            "Prepare only the authorized test identities and disposable records described in the evidence.",
            "Reproduce the documented scenario using the program-approved procedure; do not access third-party data.",
            "Capture minimal redacted request/response and before/after evidence where explicitly permitted.",
            "Stop if observed behavior differs from the documented evidence or requires an unauthorized action.",
        ],
        observed_results=[item.statement for item in observed],
        expected_behavior=[item.statement for item in expected],
        security_impact="Documented impact context (not independently verified): " + " ".join(item.statement for item in impacts),
        evidence_references=[f"evidence:{x}" for x in refs]+[f"observation:{x}" for x in obs_refs],
        unresolved_questions=[
            "Has an independent reviewer reproduced the behavior?",
            "Does the program policy explicitly classify this behavior as a security boundary violation?",
            "Is the claimed impact demonstrated without relying on assumptions?",
            "Are all affected routes and account roles within the authorized scope?",
        ],
    )

def render_finding_report_markdown(report: FindingReportDraft) -> str:
    def section(title, values):
        return "## "+title+"\n"+"\n".join(f"- {value}" for value in values)
    return "\n\n".join([
        "# "+report.title,
        report.summary,
        section("Affected surface",report.affected_surface),
        section("Prerequisites",report.prerequisites),
        section("Reproduction steps",report.reproduction_steps),
        section("Observed results",report.observed_results),
        section("Expected behavior",report.expected_behavior),
        "## Security impact\n"+report.security_impact,
        section("Evidence references",report.evidence_references),
        section("Unresolved questions",report.unresolved_questions),
        "## Assessment\nSeverity: Not assessed\nCVSS: Not assessed\nStatus: Unconfirmed draft requiring independent human validation.",
    ])
