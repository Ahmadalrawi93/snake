from datetime import datetime, timezone

import pytest

from asset_intelligence_prioritization import prioritize_assets


NOW = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)


def item(host, kind, source, observed="2026-11-17T10:00:00+00:00"):
    return {"hostname": host, "kind": kind, "source": source, "value": "example",
            "observed_at": observed}


def test_fresh_multi_source_changed_url_ranks_above_old_hostname():
    records = [
        item("old.example.org", "hostname", "crt_sh_ct", "2026-01-01T00:00:00+00:00"),
        item("api.example.org", "url", "crt_sh_ct"),
        item("api.example.org", "url", "dnsdb_passive_dns"),
    ]
    ranked = prioritize_assets(records, events=[{
        "hostname": "api.example.org", "kind": "url", "event": "new"
    }], now=NOW)
    assert ranked[0]["hostname"] == "api.example.org"
    assert ranked[0]["priority_score"] == 20 + 8 + 12 + 20
    assert ranked[0]["priority_label"] == "high"


def test_identical_input_is_deterministic():
    records = [item("b.example.org", "hostname", "ct"), item("a.example.org", "hostname", "ct")]
    first = prioritize_assets(records, now=NOW)
    second = prioritize_assets(records, now=NOW)
    assert [(x["hostname"], x["priority_score"]) for x in first] == [
        (x["hostname"], x["priority_score"]) for x in second
    ]


def test_invalid_or_future_timestamp_gets_no_freshness_bonus():
    row = item("api.example.org", "url", "ct", "not-a-time")
    assert prioritize_assets([row], now=NOW)[0]["priority_factors"]["freshness"] == 0
    future = item("api.example.org", "url", "ct", "2027-01-01T00:00:00+00:00")
    assert prioritize_assets([future], now=NOW)[0]["priority_factors"]["freshness"] == 0


def test_rejects_naive_reference_time_and_oversized_input():
    with pytest.raises(ValueError):
        prioritize_assets([], now=datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        prioritize_assets([{}] * 501, now=NOW)


def test_missing_event_does_not_boost_priority():
    row = item("api.example.org", "url", "ct")
    result = prioritize_assets([row], events=[{
        "hostname": "api.example.org", "kind": "url", "event": "missing"
    }], now=NOW)[0]
    assert result["priority_score"] == 22
    assert result["priority_label"] == "low"
