from types import SimpleNamespace
import pytest
from app.core.authorization_test_cases import build_authorization_test_case_report

def hypothesis(**kwargs):
    return SimpleNamespace(**kwargs)

def test_generates_object_and_role_cases_from_boundary_report():
    report=build_authorization_test_case_report(boundary=SimpleNamespace(hypotheses=[
        hypothesis(host="app.example.test",resource="orders",
            review_reasons=["object_reference_surface_observed","privileged_and_ordinary_surfaces_coexist"],
            supporting_observation_ids=["obs-a","obs-b"])
    ]))
    assert {x.category for x in report.cases}=={"object_ownership","role_boundary"}
    assert all(x.requires_two_authorized_test_identities for x in report.cases)
    assert report.execution_enabled is False and report.requests_generated is False

def test_generates_tenant_bulk_export_and_cross_endpoint_cases():
    report=build_authorization_test_case_report(
        tenant=SimpleNamespace(hypotheses=[hypothesis(host="app.test",resource="projects",supporting_observation_ids=["t1"])]),
        cross_endpoint=SimpleNamespace(hypotheses=[hypothesis(host="app.test",resource="orders",
            operations=[SimpleNamespace(operation_kind=x) for x in ["collection","bulk","export"]],
            supporting_observation_ids=["x1","x2"])])
    )
    assert {x.category for x in report.cases}=={"cross_tenant","bulk_authorization","export_authorization","cross_endpoint_consistency"}

def test_workflow_case_is_manual_and_state_change_gated():
    report=build_authorization_test_case_report(workflow=SimpleNamespace(hypotheses=[
        hypothesis(host="app.test",resource="payments",supporting_observation_ids=["w1"])
    ]))
    case=report.cases[0]
    assert case.category=="workflow_transition"
    assert case.state_change_requires_explicit_program_permission is True
    assert any("state-changing" in step for step in case.manual_steps)

def test_deterministic_deduplication_and_bounds():
    item=hypothesis(host="app.test",resource="orders",supporting_observation_ids=["a"])
    kwargs={"boundary":SimpleNamespace(hypotheses=[hypothesis(**{**item.__dict__,"review_reasons":["object_reference_surface_observed"]})])}
    one=build_authorization_test_case_report(**kwargs)
    two=build_authorization_test_case_report(**kwargs)
    assert one.model_dump()==two.model_dump()
    with pytest.raises(ValueError):
        build_authorization_test_case_report(max_cases=0)
