from datetime import datetime, timezone
from uuid import uuid4
import pytest
from app.core.analysis_context import build_analysis_context
from app.core.workflow_reasoning import build_workflow_reasoning
from app.schemas.worker_results import WorkerObservation

def obs(url):
    return WorkerObservation(observation_id=uuid4(), kind="url", value=url,
        evidence="passive route", source="ct", observed_at=datetime.now(timezone.utc))

def test_groups_multiple_business_actions_by_host_and_resource():
    items=[obs("https://shop.example.test/api/orders/approve"),
           obs("https://shop.example.test/api/orders/123/refund"),
           obs("https://shop.example.test/api/orders/123/cancel")]
    report=build_workflow_reasoning(build_analysis_context(items))
    assert len(report.hypotheses)==1
    item=report.hypotheses[0]
    assert item.resource=="orders"
    assert item.observed_actions==["approve","cancel","refund"]
    assert "refund->cancel" in item.possible_transition_pairs
    assert item.ordering_status=="unknown_from_passive_observations"
    assert set(item.supporting_observation_ids)=={str(x.observation_id) for x in items}
    assert report.execution_enabled is False and report.confirmed is False

def test_does_not_mix_hosts_or_resources():
    report=build_workflow_reasoning(build_analysis_context([
        obs("https://a.example.test/orders/approve"),
        obs("https://a.example.test/orders/refund"),
        obs("https://b.example.test/orders/approve"),
        obs("https://b.example.test/orders/refund"),
        obs("https://a.example.test/accounts/transfer"),
    ]))
    assert len(report.hypotheses)==2
    assert {(x.host,x.resource) for x in report.hypotheses}=={
        ("a.example.test","orders"),("b.example.test","orders")}

def test_one_action_does_not_invent_transition():
    report=build_workflow_reasoning(build_analysis_context([
        obs("https://shop.example.test/orders/refund")]))
    assert report.hypotheses==[]

def test_query_credentials_and_non_url_are_not_used():
    report=build_workflow_reasoning(build_analysis_context([
        obs("https://user:pass@shop.example.test/orders/refund?next=/orders/pay"),
        obs("not-a-url")]))
    assert report.hypotheses==[]

def test_rejects_invalid_limit():
    with pytest.raises(ValueError):
        build_workflow_reasoning(build_analysis_context([]),max_hypotheses=0)
