from datetime import datetime, timezone
from uuid import uuid4
import pytest
from app.core.analysis_context import build_analysis_context
from app.core.cross_endpoint_authorization import build_cross_endpoint_authorization_report
from app.schemas.worker_results import WorkerObservation

def obs(url):
    return WorkerObservation(observation_id=uuid4(),kind="url",value=url,
        evidence="passive route",source="ct",observed_at=datetime.now(timezone.utc))

def test_correlates_collection_object_and_named_action():
    items=[obs("https://shop.example.test/api/orders"),
           obs("https://shop.example.test/api/orders/123"),
           obs("https://shop.example.test/api/orders/refund")]
    report=build_cross_endpoint_authorization_report(build_analysis_context(items))
    assert len(report.hypotheses)==1
    item=report.hypotheses[0]
    assert item.resource=="orders"
    assert {x.operation_kind for x in item.operations}=={"collection","object","named_action"}
    assert "object_and_collection_surfaces_coexist" in item.review_reasons
    assert set(item.supporting_observation_ids)=={str(x.observation_id) for x in items}
    assert report.confirmed is False and report.execution_enabled is False

def test_highlights_bulk_and_export_surfaces():
    report=build_cross_endpoint_authorization_report(build_analysis_context([
        obs("https://app.example.test/api/invoices"),
        obs("https://app.example.test/api/invoices/bulk/delete"),
        obs("https://app.example.test/api/invoices/export"),
    ]))
    assert len(report.hypotheses)==1
    assert "bulk_or_export_surface_observed" in report.hypotheses[0].review_reasons

def test_isolates_hosts_and_resources():
    report=build_cross_endpoint_authorization_report(build_analysis_context([
        obs("https://a.example.test/orders"),obs("https://a.example.test/orders/123"),
        obs("https://b.example.test/orders"),obs("https://b.example.test/orders/123"),
        obs("https://a.example.test/users"),obs("https://a.example.test/users/123"),
    ]))
    assert {(x.host,x.resource) for x in report.hypotheses}=={
        ("a.example.test","orders"),("b.example.test","orders"),("a.example.test","users")}

def test_ignores_credentials_queries_and_non_resource_routes():
    report=build_cross_endpoint_authorization_report(build_analysis_context([
        obs("https://user:pass@app.example.test/orders"),
        obs("https://app.example.test/orders?next=/orders/123"),
        obs("https://app.example.test/static/app.js"),
    ]))
    assert report.hypotheses==[]

def test_single_operation_class_does_not_create_hypothesis():
    report=build_cross_endpoint_authorization_report(build_analysis_context([
        obs("https://app.example.test/api/orders"),
        obs("https://app.example.test/api/orders/archive"),
    ]))
    assert report.hypotheses==[]

def test_rejects_invalid_limit():
    with pytest.raises(ValueError):
        build_cross_endpoint_authorization_report(build_analysis_context([]),max_hypotheses=0)
