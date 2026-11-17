import json
import os

import pytest

from passive_feed_scheduler import run_cycle, _acquire_lock


def test_cycle_combines_providers_and_writes_private_feed(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["example.org"]}))
    scope.chmod(0o600)
    output = tmp_path / "feed.json"
    calls = []
    def ct(rules):
        calls.append(("ct", rules))
        return [{"hostname": "example.org", "kind": "hostname", "value": "example.org",
                 "evidence": "ct", "source": "ct", "observed_at": "2026-01-01T00:00:00+00:00"}]
    def dnsdb(rules, key):
        calls.append(("dnsdb", rules, key))
        return [{"hostname": "example.org", "kind": "dns_record", "value": "A 192.0.2.1",
                 "evidence": "dns", "source": "dnsdb", "observed_at": "2026-01-01T00:00:00+00:00"}]
    count = run_cycle(str(scope), str(output), ["ct", "dnsdb"], "ticket-1",
                      ct_collector=ct, dnsdb_collector=dnsdb,
                      environ={"DNSDB_API_KEY": "test-key"})
    assert count == 2
    assert [item["kind"] for item in json.loads(output.read_text())] == ["hostname", "dns_record"]
    assert output.stat().st_mode & 0o777 == 0o600
    assert calls[0] == ("ct", ["example.org"])
    assert calls[1] == ("dnsdb", ["example.org"], "test-key")


def test_cycle_reloads_scope_each_time(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["example.org"]}))
    scope.chmod(0o600)
    observed = []
    def collector(rules):
        observed.append(list(rules))
        return []
    run_cycle(str(scope), str(tmp_path / "feed.json"), ["ct"], "ticket",
              ct_collector=collector)
    scope.write_text(json.dumps({"approved_scope_rules": ["new.example.org"]}))
    run_cycle(str(scope), str(tmp_path / "feed.json"), ["ct"], "ticket",
              ct_collector=collector)
    assert observed == [["example.org"], ["new.example.org"]]


def test_failed_source_does_not_replace_previous_feed(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["*.example.org"]}))
    scope.chmod(0o600)
    output = tmp_path / "feed.json"
    output.write_text('[{"known_good":true}]')
    with pytest.raises(RuntimeError):
        run_cycle(str(scope), str(output), ["ct"], "ticket",
                  ct_collector=lambda _rules: (_ for _ in ()).throw(RuntimeError("provider down")))
    assert json.loads(output.read_text()) == [{"known_good": True}]


def test_dnsdb_cycle_requires_key_without_exposing_it(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["*.example.org"]}))
    scope.chmod(0o600)
    with pytest.raises(ValueError, match="DNSDB_API_KEY"):
        run_cycle(str(scope), str(tmp_path / "feed.json"), ["dnsdb"], "ticket",
                  environ={})


def test_lock_rejects_second_process_and_symlink(tmp_path):
    lock = tmp_path / "scheduler.lock"
    fd = _acquire_lock(str(lock))
    try:
        with pytest.raises(RuntimeError, match="already running"):
            _acquire_lock(str(lock))
    finally:
        os.close(fd)
    target = tmp_path / "target"
    target.write_text("")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        _acquire_lock(str(link))


def test_scheduler_records_asset_changes_after_successful_feed_publish(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["*.example.org"]}))
    scope.chmod(0o600)
    output = tmp_path / "feed.json"
    history = tmp_path / "history.sqlite3"
    record = {"hostname": "api.example.org", "kind": "hostname", "value": "api.example.org",
              "source": "ct_sh_ct", "evidence": "certificate", "observed_at": "2026-11-17T00:00:00+00:00"}
    run_cycle(str(scope), str(output), ["ct"], "ticket",
              ct_collector=lambda _rules: [record], history_db=str(history))
    assert history.exists()
    run_cycle(str(scope), str(output), ["ct"], "ticket",
              ct_collector=lambda _rules: [], history_db=str(history))
    import sqlite3
    connection = sqlite3.connect(history)
    event_types = [row[0] for row in connection.execute(
        "SELECT event_type FROM asset_change_events ORDER BY id"
    )]
    connection.close()
    assert event_types == ["new", "missing"]


def test_scheduler_writes_separate_priority_report(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["*.example.org"]}))
    scope.chmod(0o600)
    output = tmp_path / "feed.json"
    priority = tmp_path / "priority.json"
    history = tmp_path / "history.sqlite3"
    record = {"hostname": "api.example.org", "kind": "url", "value": "https://api.example.org/v1",
              "source": "crt_sh_ct", "evidence": "ct", "observed_at": "2026-11-17T10:00:00+00:00"}
    run_cycle(str(scope), str(output), ["ct"], "ticket",
              ct_collector=lambda _rules: [record], history_db=str(history),
              priority_report=str(priority))
    feed = json.loads(output.read_text())
    ranked = json.loads(priority.read_text())
    assert "priority_score" not in feed[0]
    assert ranked[0]["priority_score"] > 0
    assert ranked[0]["priority_label"] in {"low", "medium", "high"}
    assert priority.stat().st_mode & 0o777 == 0o600


def test_scheduler_writes_separate_passive_graph(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["*.example.org"]}))
    scope.chmod(0o600)
    output = tmp_path / "feed.json"
    graph_path = tmp_path / "graph.json"
    history = tmp_path / "history.sqlite3"
    record = {"hostname": "api.example.org", "kind": "url",
              "value": "https://api.example.org/v1/users", "source": "ct_sh_ct",
              "evidence": "passive", "observed_at": "2026-11-17T10:00:00+00:00"}
    run_cycle(str(scope), str(output), ["ct"], "ticket",
              ct_collector=lambda _rules: [record], history_db=str(history),
              graph_report=str(graph_path))
    feed = json.loads(output.read_text())
    graph = json.loads(graph_path.read_text())
    assert "id" not in feed[0]
    assert graph["classification"] == "passive_unconfirmed_attack_surface_graph"
    assert graph["summary"]["api_route_hints"] == 1
    assert graph["execution_enabled"] is False
    assert graph_path.stat().st_mode & 0o777 == 0o600


def test_scheduler_writes_separate_api_endpoint_report(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["*.example.org"]}))
    scope.chmod(0o600)
    output = tmp_path / "feed.json"
    endpoint_path = tmp_path / "api-endpoints.json"
    record = {"hostname": "api.example.org", "kind": "url",
              "value": "https://api.example.org/v2/accounts/123",
              "source": "ct_sh_ct", "evidence": "passive",
              "observed_at": "2026-11-17T10:00:00+00:00"}
    run_cycle(str(scope), str(output), ["ct"], "ticket",
              ct_collector=lambda _rules: [record],
              endpoint_report=str(endpoint_path))
    feed = json.loads(output.read_text())
    report = json.loads(endpoint_path.read_text())
    assert "priority_score" not in feed[0]
    assert report["classification"] == "passive_unconfirmed_api_endpoint_hints"
    assert report["endpoints"][0]["path_template"] == "/v2/accounts/{id}"
    assert report["execution_enabled"] is False
    assert endpoint_path.stat().st_mode & 0o777 == 0o600


def test_scheduler_writes_separate_business_logic_hypotheses(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"approved_scope_rules": ["*.example.org"]}))
    scope.chmod(0o600)
    output = tmp_path / "feed.json"
    report_path = tmp_path / "business-logic.json"
    records = [
        {"hostname": "api.example.org", "kind": "url",
         "value": "https://api.example.org/v1/orders", "source": "ct",
         "evidence": "passive", "observed_at": "2026-11-17T10:00:00+00:00"},
        {"hostname": "api.example.org", "kind": "url",
         "value": "https://api.example.org/v1/orders/123", "source": "dnsdb",
         "evidence": "passive", "observed_at": "2026-11-17T10:01:00+00:00"},
        {"hostname": "api.example.org", "kind": "url",
         "value": "https://api.example.org/v1/orders/123/refund", "source": "ct",
         "evidence": "passive", "observed_at": "2026-11-17T10:02:00+00:00"},
    ]
    run_cycle(str(scope), str(output), ["ct"], "ticket",
              ct_collector=lambda _rules: records,
              business_logic_report=str(report_path))
    report = json.loads(report_path.read_text())
    assert report["classification"] == "passive_unconfirmed_business_logic_hypotheses"
    assert report["summary"]["object_authorization"] == 1
    assert report["summary"]["sensitive_business_operation"] == 1
    assert report["summary"]["confirmed"] == 0
    assert report_path.stat().st_mode & 0o777 == 0o600
