from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.analysis_context import build_analysis_context
from app.core.business_logic_intelligence import build_business_logic_profile
from app.core.cross_surface_reasoning import build_cross_surface_profile
from app.core.validation_strategy import build_validation_strategy
from app.schemas.observation_triage import ObservationTriage
from app.schemas.worker_results import WorkerObservation


def obs(url):
    return WorkerObservation(
        observation_id=uuid4(), kind="url", value=url, evidence="observed route",
        source="passive", observed_at=datetime.now(timezone.utc),
    )


def make_inputs(urls, category="business_logic", confidence="medium"):
    items = [obs(url) for url in urls]
    context = build_analysis_context(items)
    ids = [oid for group in context.groups for item in group.observations for oid in item.observation_ids]
    ids += [oid for item in context.ungrouped for oid in item.observation_ids]
    triage = ObservationTriage(
        category=category, hypothesis="Review the observed application behavior.",
        supporting_observation_ids=[uuid4() if False else __import__("uuid").UUID(ids[0])],
        missing_evidence=["Documented expected behavior"],
        validation_questions=["What is the expected behavior for an authorized test account?"],
        confidence=confidence,
    )
    business = build_business_logic_profile(context)
    cross = build_cross_surface_profile(context, business)
    return context, triage, business, cross


def test_builds_manual_only_strategy_from_evidence():
    context, triage, business, cross = make_inputs([
        "https://app.example.test/login",
        "https://app.example.test/api/orders",
        "https://app.example.test/api/orders/123",
        "https://app.example.test/api/orders/123/approve",
    ])
    plan = build_validation_strategy(context, triage, business, cross)
    assert plan.status == "review_required"
    assert len(plan.items) >= 2
    assert all(item.execution_mode == "manual_human_review_only" for item in plan.items)
    assert all(item.disposition == "requires_independent_validation" for item in plan.items)
    assert all(item.supporting_observation_ids for item in plan.items)
    assert "no requests" in plan.safety_constraints
    assert all("authorization" in item.lower() or "scope" in item.lower() for item in plan.global_prerequisites)


def test_all_strategy_evidence_must_exist_in_context():
    context, triage, business, cross = make_inputs(["https://app.example.test/api/users"])
    triage.supporting_observation_ids = [uuid4()]
    with pytest.raises(ValueError):
        build_validation_strategy(context, triage, business, cross)


def test_plan_does_not_invent_object_surface_without_paired_routes():
    context, triage, business, cross = make_inputs(["https://app.example.test/api/users/123"])
    plan = build_validation_strategy(context, triage, business, cross)
    assert not any(item.strategy_id == "business_object_authorization" for item in plan.items)


def test_auth_and_object_links_prioritize_object_authorization_review():
    context, triage, business, cross = make_inputs([
        "https://app.example.test/login",
        "https://app.example.test/api/users",
        "https://app.example.test/api/users/123",
    ])
    plan = build_validation_strategy(context, triage, business, cross)
    object_item = next(item for item in plan.items if item.strategy_id == "cross_auth_object")
    assert object_item.priority == "high"
    assert "shared controls" in object_item.priority_basis


def test_rejects_invalid_plan_limit():
    context, triage, business, cross = make_inputs(["https://app.example.test/api/users"])
    with pytest.raises(ValueError):
        build_validation_strategy(context, triage, business, cross, max_items=0)
