from business_logic_correlation import correlate_business_logic


def endpoint(path, host="api.example.org", source="ct"):
    return {"hostname": host, "path_template": path, "evidence": [
        {"source": source, "observed_at": "2026-11-17T10:00:00+00:00"}
    ]}


def test_correlates_collection_and_object_route_for_authorization_review():
    report = correlate_business_logic([
        endpoint("/v1/orders"),
        endpoint("/v1/orders/{id}"),
    ])
    assert report["summary"]["object_authorization"] == 1
    hypothesis = report["hypotheses"][0]
    assert hypothesis["category"] == "object_authorization"
    assert hypothesis["related_routes"] == ["/v1/orders", "/v1/orders/{id}"]
    assert hypothesis["confirmed"] is False
    assert hypothesis["disposition"] == "requires_independent_validation"


def test_correlates_sensitive_action_and_builds_workflow_questions():
    report = correlate_business_logic([
        endpoint("/v1/orders/{id}/refund"),
        endpoint("/v1/accounts/{id}/transfer"),
    ])
    assert report["summary"]["sensitive_business_operation"] == 2
    assert {x["action"] for x in report["hypotheses"]} == {"refund", "transfer"}
    assert all(any("state transition" in q for q in x["validation_questions"])
               for x in report["hypotheses"])


def test_keeps_hosts_separate_and_deduplicates_deterministically():
    records = [
        endpoint("/orders", "a.example.org"),
        endpoint("/orders/{id}", "a.example.org"),
        endpoint("/orders", "b.example.org"),
        endpoint("/orders/{id}", "b.example.org"),
    ]
    first = correlate_business_logic(records)
    second = correlate_business_logic(list(reversed(records)))
    assert first == second
    assert {x["host"] for x in first["hypotheses"]} == {"a.example.org", "b.example.org"}


def test_object_route_alone_does_not_create_idor_hypothesis():
    report = correlate_business_logic([endpoint("/users/{id}")])
    assert report["hypotheses"] == []
    assert report["summary"]["confirmed"] == 0


def test_ignores_malformed_records_and_rejects_oversized_input():
    report = correlate_business_logic([{}, {"hostname": "api.example.org", "path_template": "users"}])
    assert report["hypotheses"] == []
    import pytest
    with pytest.raises(ValueError):
        correlate_business_logic([{}] * 1001)
