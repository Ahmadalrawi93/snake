from api_endpoint_intelligence import build_api_endpoint_intelligence


def rec(host, value, source="ct"):
    return {"hostname": host, "kind": "url", "value": value, "source": source,
            "observed_at": "2026-11-17T10:00:00+00:00"}


def test_extracts_scoped_endpoint_and_classifies_without_guessing_method():
    result = build_api_endpoint_intelligence(
        [rec("api.example.org", "https://api.example.org/v1/users/123")],
        ["*.example.org"],
    )
    assert result["summary"]["endpoints"] == 1
    endpoint = result["endpoints"][0]
    assert endpoint["path_template"] == "/v1/users/{id}"
    assert {"api_versioned", "identity"} <= set(endpoint["categories"])
    assert endpoint["method"] == "unknown"
    assert result["execution_enabled"] is False


def test_deduplicates_templates_and_retains_distinct_passive_sources():
    result = build_api_endpoint_intelligence([
        rec("api.example.org", "https://api.example.org/users/123", "ct"),
        rec("api.example.org", "https://api.example.org/users/456", "dnsdb"),
    ], ["*.example.org"])
    assert len(result["endpoints"]) == 1
    assert {e["source"] for e in result["endpoints"][0]["evidence"]} == {"ct", "dnsdb"}


def test_rejects_out_of_scope_host_mismatch_query_and_credentials():
    records = [
        rec("outside.test", "https://outside.test/api/v1"),
        rec("api.example.org", "https://other.example.org/api/v1"),
        rec("api.example.org", "https://api.example.org/api/v1?token=secret"),
        rec("api.example.org", "https://user:pass@api.example.org/api/v1"),
    ]
    result = build_api_endpoint_intelligence(records, ["*.example.org"])
    assert result["endpoints"] == []


def test_exact_scope_does_not_include_subdomains():
    result = build_api_endpoint_intelligence(
        [rec("api.example.org", "https://api.example.org/v1")],
        ["example.org"],
    )
    assert result["endpoints"] == []


def test_rejects_oversized_input():
    import pytest
    with pytest.raises(ValueError):
        build_api_endpoint_intelligence([{}] * 501, ["example.org"])


def test_extracts_object_reference_and_business_operation_review_hints():
    result = build_api_endpoint_intelligence(
        [rec("api.example.org", "https://api.example.org/v1/orders/123/refund")],
        ["*.example.org"],
    )
    endpoint = result["endpoints"][0]
    assert endpoint["resource_segments"] == ["orders"]
    assert endpoint["action_segments"] == ["refund"]
    assert endpoint["object_reference_present"] is True
    assert "object_reference_authorization_review" in endpoint["business_logic_review_hints"]
    assert "named_business_operation_manual_review" in endpoint["business_logic_review_hints"]
    assert endpoint["method"] == "unknown"


def test_rejects_malformed_ports_and_naive_timestamps():
    malformed = rec("api.example.org", "https://api.example.org:99999/v1")
    naive = rec("api.example.org", "https://api.example.org/v1")
    naive["observed_at"] = "2026-11-17T10:00:00"
    result = build_api_endpoint_intelligence([malformed, naive], ["*.example.org"])
    assert result["endpoints"] == []


def test_rejects_control_characters_and_oversized_urls():
    control = rec("api.example.org", "https://api.example.org/v1\n")
    oversized = rec("api.example.org", "https://api.example.org/" + "a" * 5000)
    result = build_api_endpoint_intelligence([control, oversized], ["*.example.org"])
    assert result["endpoints"] == []
