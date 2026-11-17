from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.analysis_context import build_analysis_context
from app.core.business_logic_intelligence import build_business_logic_profile
from app.schemas.worker_results import WorkerObservation


def obs(url):
    return WorkerObservation(
        observation_id=uuid4(), kind="url", value=url, evidence="observed route",
        source="passive", observed_at=datetime.now(timezone.utc),
    )


def test_links_collection_object_and_sensitive_action_to_observations():
    items = [
        obs("https://shop.example.test/api/orders"),
        obs("https://shop.example.test/api/orders/123"),
        obs("https://shop.example.test/api/orders/123/approve"),
    ]
    profile = build_business_logic_profile(build_analysis_context(items))
    assert len(profile.object_surfaces) == 1
    surface = profile.object_surfaces[0]
    assert surface.resource == "orders"
    assert surface.collection_route == "/api/orders"
    assert surface.object_route == "/api/orders/:id"
    assert set(surface.observation_ids) == {str(x.observation_id) for x in items[:2]}
    assert any(x.action == "approve" for x in profile.action_surfaces)
    assert {x.category for x in profile.hypotheses} == {"object_authorization", "sensitive_action"}
    assert all(x.disposition == "requires_independent_validation" for x in profile.hypotheses)


def test_never_infers_roles_methods_or_workflow_from_names():
    profile = build_business_logic_profile(build_analysis_context([
        obs("https://app.example.test/admin/users"),
        obs("https://app.example.test/api/payments"),
    ]))
    assert profile.action_surfaces == []
    assert all("actual behavior is unknown" in x.statement or "may warrant" in x.statement for x in profile.hypotheses)
    assert "do not establish HTTP methods" in profile.limitations


def test_ignores_unrecognized_and_malformed_routes():
    profile = build_business_logic_profile(build_analysis_context([
        obs("https://app.example.test/random/thing"),
        obs("not-a-url"),
    ]))
    assert profile.object_surfaces == []
    assert profile.action_surfaces == []
    assert profile.hypotheses == []


def test_rejects_invalid_surface_limit():
    with pytest.raises(ValueError):
        build_business_logic_profile(build_analysis_context([]), max_surfaces=0)


def test_object_route_without_observed_collection_does_not_claim_collection_relationship():
    profile = build_business_logic_profile(build_analysis_context([
        obs("https://app.example.test/api/users/123"),
    ]))
    assert len(profile.object_surfaces) == 1
    assert profile.object_surfaces[0].object_route is None
    assert not any(x.category == "object_authorization" for x in profile.hypotheses)


def test_nested_action_route_does_not_pollute_object_surface_evidence():
    items = [
        obs("https://app.example.test/api/users"),
        obs("https://app.example.test/api/users/123"),
        obs("https://app.example.test/api/users/123/delete"),
    ]
    profile = build_business_logic_profile(build_analysis_context(items))
    assert set(profile.object_surfaces[0].observation_ids) == {str(x.observation_id) for x in items[:2]}
