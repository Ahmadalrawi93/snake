from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.analysis_context import build_analysis_context
from app.core.application_profile import build_application_profile
from app.schemas.worker_results import WorkerObservation


def obs(kind, value, evidence="observed"):
    return WorkerObservation(
        observation_id=uuid4(), kind=kind, value=value, evidence=evidence,
        source="passive", observed_at=datetime.now(timezone.utc),
    )


def test_profile_groups_observed_hosts_and_normalizes_object_routes():
    first = obs("url", "https://app.example.test/api/users/123?token=secret")
    second = obs("url", "https://app.example.test/api/users/456")
    context = build_analysis_context([first, second])
    profile = build_application_profile(context)

    assert [host.hostname for host in profile.hosts] == ["app.example.test"]
    assert len(profile.routes) == 1
    route = profile.routes[0]
    assert route.route_template == "/api/users/:id"
    assert "object_access" in route.surfaces
    assert set(route.observation_ids) == {str(first.observation_id), str(second.observation_id)}
    assert "secret" not in route.route_template


def test_profile_uses_only_explicit_technology_and_identifying_headers():
    tech = obs("technology", "Django 5.0")
    server = obs("http_header", "Server: nginx")
    unrelated = obs("http_header", "Content-Type: application/json")
    context = build_analysis_context([tech, server, unrelated])
    profile = build_application_profile(context)

    names = {item.name for item in profile.technologies}
    assert names == {"Django 5.0", "Server: nginx"}
    assert all(item.observation_ids for item in profile.technologies)


def test_profile_does_not_infer_framework_or_behavior_from_route_names():
    context = build_analysis_context([obs("url", "https://example.test/admin/login")])
    profile = build_application_profile(context)
    assert profile.technologies == []
    assert set(profile.routes[0].surfaces) == {"admin", "authentication"}
    assert "not verified" in profile.limitations


def test_profile_redacts_credentials_in_technology_values_when_built_from_redacted_context():
    from app.core.analysis_redaction import redact_analysis_context
    context = build_analysis_context([obs("technology", "api_key=supersecret")])
    profile = build_application_profile(redact_analysis_context(context))
    assert "supersecret" not in profile.technologies[0].name


def test_rejects_invalid_route_limit():
    context = build_analysis_context([])
    with pytest.raises(ValueError):
        build_application_profile(context, max_routes=0)
