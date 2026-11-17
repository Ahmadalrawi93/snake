from datetime import datetime, timezone
from uuid import uuid4

from app.core.analysis_context import build_analysis_context
from app.core.business_logic_intelligence import build_business_logic_profile
from app.core.cross_surface_reasoning import build_cross_surface_profile
from app.schemas.worker_results import WorkerObservation


def obs(url):
    return WorkerObservation(
        observation_id=uuid4(), kind="url", value=url, evidence="observed route",
        source="passive", observed_at=datetime.now(timezone.utc),
    )


def profile(urls):
    context = build_analysis_context([obs(url) for url in urls])
    business = build_business_logic_profile(context)
    return context, business, build_cross_surface_profile(context, business)


def test_links_auth_object_and_sensitive_action_only_by_shared_host():
    context, business, result = profile([
        "https://app.example.test/login",
        "https://app.example.test/api/orders",
        "https://app.example.test/api/orders/123",
        "https://app.example.test/api/orders/123/approve",
    ])
    relations = {item.relation for item in result.links}
    assert relations == {
        "authentication_to_object_surface",
        "authentication_to_sensitive_action",
        "object_to_sensitive_action",
    }
    all_ids = {oid for item in result.links for oid in item.observation_ids}
    assert len(all_ids) == 4
    assert all(item.disposition == "requires_independent_validation" for item in result.links)
    assert all("unknown" in item.rationale or "unproven" in item.rationale for item in result.links)


def test_different_hosts_are_not_cross_correlated():
    context, business, result = profile([
        "https://auth.example.test/login",
        "https://api.example.test/api/users",
        "https://api.example.test/api/users/123",
        "https://billing.example.test/api/payments/123/pay",
    ])
    assert result.links == []


def test_auth_and_object_routes_without_sensitive_action_only_link_auth_object():
    context, business, result = profile([
        "https://app.example.test/auth/login",
        "https://app.example.test/api/users",
        "https://app.example.test/api/users/123",
    ])
    assert [item.relation for item in result.links] == ["authentication_to_object_surface"]


def test_no_authentication_surface_means_no_auth_claim():
    context, business, result = profile([
        "https://app.example.test/api/orders",
        "https://app.example.test/api/orders/123",
        "https://app.example.test/api/orders/123/delete",
    ])
    assert {item.relation for item in result.links} == {"object_to_sensitive_action"}
    assert all("authentication" not in item.relation for item in result.links)


def test_rejects_invalid_limit():
    import pytest
    context, business, _ = profile([])
    with pytest.raises(ValueError):
        build_cross_surface_profile(context, business, max_links=0)


def test_collection_route_without_identifier_route_does_not_create_object_cross_link():
    context, business, result = profile([
        "https://app.example.test/login",
        "https://app.example.test/api/users",
    ])
    assert result.links == []
