from datetime import datetime, timezone
from uuid import uuid4
import pytest
from app.core.analysis_context import build_analysis_context
from app.core.authorization_boundary import build_authorization_boundary_report
from app.schemas.worker_results import WorkerObservation

def obs(url):
    return WorkerObservation(observation_id=uuid4(), kind="url", value=url,
        evidence="passive route", source="ct", observed_at=datetime.now(timezone.utc))

def test_detects_privileged_and_object_reference_surfaces():
    items=[obs("https://shop.example.test/api/admin/orders"),
           obs("https://shop.example.test/api/orders"),
           obs("https://shop.example.test/api/orders/123")]
    report=build_authorization_boundary_report(build_analysis_context(items))
    assert len(report.hypotheses)==1
    item=report.hypotheses[0]
    assert item.resource=="orders"
    assert "privileged_and_ordinary_surfaces_coexist" in item.review_reasons
    assert "object_reference_surface_observed" in item.review_reasons
    assert {s.surface_kind for s in item.surfaces}=={"privileged","ordinary","object_reference"}
    assert set(item.supporting_observation_ids)=={str(x.observation_id) for x in items}
    assert report.execution_enabled is False and report.confirmed is False

def test_keeps_hosts_and_resources_isolated():
    report=build_authorization_boundary_report(build_analysis_context([
        obs("https://a.example.test/admin/users"),
        obs("https://a.example.test/users"),
        obs("https://b.example.test/admin/users"),
        obs("https://b.example.test/users"),
        obs("https://a.example.test/admin/orders"),
        obs("https://a.example.test/orders"),
    ]))
    assert {(x.host,x.resource) for x in report.hypotheses}=={
        ("a.example.test","users"),("b.example.test","users"),("a.example.test","orders")}

def test_role_permission_routes_are_review_hints_not_proof():
    report=build_authorization_boundary_report(build_analysis_context([
        obs("https://app.example.test/api/roles"),
        obs("https://app.example.test/api/roles/permissions"),
    ]))
    assert len(report.hypotheses)==1
    assert "role_or_permission_surface_observed" in report.hypotheses[0].review_reasons

def test_ignores_unrelated_routes_and_unsafe_url_forms():
    report=build_authorization_boundary_report(build_analysis_context([
        obs("https://user:pass@app.example.test/orders/123"),
        obs("https://app.example.test/orders/123?next=/admin"),
        obs("https://app.example.test/static/app.js"),
    ]))
    assert report.hypotheses==[]

def test_rejects_invalid_report_limit():
    with pytest.raises(ValueError):
        build_authorization_boundary_report(build_analysis_context([]),max_hypotheses=0)
