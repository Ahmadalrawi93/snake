from datetime import datetime, timezone
from uuid import uuid4
import pytest
from app.core.analysis_context import build_analysis_context
from app.core.tenant_isolation import build_tenant_isolation_report
from app.schemas.worker_results import WorkerObservation

def obs(url):
    return WorkerObservation(observation_id=uuid4(),kind="url",value=url,
        evidence="passive route",source="ct",observed_at=datetime.now(timezone.utc))

def test_detects_tenant_and_unscoped_resource_surfaces():
    items=[obs("https://app.example.test/api/orgs/123/projects"),
           obs("https://app.example.test/api/projects"),
           obs("https://app.example.test/api/orgs/123/projects/456")]
    report=build_tenant_isolation_report(build_analysis_context(items))
    assert len(report.hypotheses)==1
    item=report.hypotheses[0]
    assert item.resource=="projects"
    assert "tenant_and_unscoped_surfaces_coexist" in item.review_reasons
    assert "tenant_object_reference_observed" in item.review_reasons
    assert set(item.supporting_observation_ids)=={str(x.observation_id) for x in items}
    assert report.execution_enabled is False and report.confirmed is False

def test_keeps_hosts_and_resources_isolated():
    report=build_tenant_isolation_report(build_analysis_context([
        obs("https://a.example.test/tenants/1/users"),
        obs("https://a.example.test/users"),
        obs("https://b.example.test/tenants/1/users"),
        obs("https://b.example.test/users"),
        obs("https://a.example.test/tenants/1/orders"),
        obs("https://a.example.test/orders"),
    ]))
    assert {(x.host,x.resource) for x in report.hypotheses}=={
        ("a.example.test","users"),("b.example.test","users"),("a.example.test","orders")}

def test_detects_multiple_tenant_context_markers():
    report=build_tenant_isolation_report(build_analysis_context([
        obs("https://app.example.test/orgs/1/projects"),
        obs("https://app.example.test/workspaces/2/projects"),
    ]))
    assert len(report.hypotheses)==1
    assert "multiple_tenant_scopes_observed" in report.hypotheses[0].review_reasons

def test_ignores_credentials_queries_and_unrelated_routes():
    report=build_tenant_isolation_report(build_analysis_context([
        obs("https://user:pass@app.example.test/orgs/1/projects"),
        obs("https://app.example.test/orgs/1/projects?next=/projects"),
        obs("https://app.example.test/static/app.js"),
    ]))
    assert report.hypotheses==[]

def test_rejects_invalid_limit():
    with pytest.raises(ValueError):
        build_tenant_isolation_report(build_analysis_context([]),max_hypotheses=0)
