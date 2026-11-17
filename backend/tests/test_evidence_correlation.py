from datetime import datetime, timezone
from uuid import uuid4

from app.core.analysis_context import build_analysis_context
from app.core.evidence_correlation import correlate_analysis_context
from app.schemas.worker_results import WorkerObservation


def obs(kind, value):
    return WorkerObservation(
        observation_id=uuid4(), kind=kind, value=value,
        evidence="passive observation", source="test",
        observed_at=datetime.now(timezone.utc),
    )


def test_correlates_same_host_and_auth_surface_without_claiming_vulnerability():
    context = build_analysis_context([
        obs("url", "https://example.test/api/login"),
        obs("url", "https://example.test/api/logout"),
    ])
    report = correlate_analysis_context(context)
    relations = {link.relation for link in report.links}
    assert "same_host" in relations
    assert "authentication_surface" in relations
    assert "vulnerabilities" in report.analysis_notice.lower() or "not vulnerabilities" in report.analysis_notice.lower()


def test_groups_numeric_object_routes_by_route_shape():
    context = build_analysis_context([
        obs("url", "https://example.test/api/users/123"),
        obs("url", "https://example.test/api/users/456"),
    ])
    report = correlate_analysis_context(context)
    assert any(link.relation == "same_route_family" for link in report.links)
    assert any(link.relation == "potential_object_access_surface" for link in report.links)


def test_keeps_unrelated_evidence_unlinked():
    context = build_analysis_context([
        obs("url", "https://one.test/status"),
        obs("url", "https://two.test/health"),
    ])
    report = correlate_analysis_context(context)
    assert len(report.uncorrelated_observation_ids) == 2


def test_rejects_invalid_link_limit():
    context = build_analysis_context([])
    try:
        correlate_analysis_context(context, max_links=0)
    except ValueError as exc:
        assert "limit" in str(exc)
    else:
        raise AssertionError("invalid limit accepted")
