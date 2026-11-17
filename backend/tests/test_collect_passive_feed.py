import json
import os
from datetime import datetime, timezone

import pytest

from collect_passive_feed import collect_ct_feed, load_scope, write_feed


def row(names, cert_id="123"):
    return {
        "id": cert_id, "name_value": names,
        "issuer_name": "Example CA", "not_before": "2026-01-02T03:04:05Z",
    }


def test_ct_collector_keeps_only_scope_and_normalizes_wildcards():
    calls = []
    def fetcher(query):
        calls.append(query)
        return [row("api.example.org\n*.example.org\noutside.invalid\nnotexample.org")]
    records = collect_ct_feed(["*.example.org"], fetcher=fetcher)
    assert calls == ["example.org", "%.example.org"]
    assert {item["hostname"] for item in records} == {"api.example.org", "example.org"}
    assert all(item["source"] == "crt_sh_ct" for item in records)
    assert all(item["kind"] == "hostname" for item in records)


def test_exact_scope_does_not_expand_to_subdomains():
    records = collect_ct_feed(["example.org"], fetcher=lambda _q: [
        row("example.org\napi.example.org")
    ])
    assert [item["hostname"] for item in records] == ["example.org"]


def test_collector_deduplicates_and_ignores_malformed_rows():
    records = collect_ct_feed(["example.org"], fetcher=lambda _q: [
        row("api.example.org"), row("api.example.org", "123"),
        {"name_value": 4}, row("bad name.example.org"),
        {"name_value": "other.example.org", "id": "2", "not_before": "not-a-date"},
    ])
    assert len(records) == 1


def test_scope_file_is_strict_and_private(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"approved_scope_rules": ["example.org", "*.api.example.org"]}))
    path.chmod(0o600)
    assert load_scope(path) == ["example.org", "*.api.example.org"]
    path.chmod(0o666)
    with pytest.raises(ValueError, match="writable"):
        load_scope(path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        load_scope(link)


def test_scope_file_rejects_extra_fields_and_bad_rules(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"approved_scope_rules": ["example.org"], "approved": True}))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="only approved_scope_rules"):
        load_scope(path)
    path.write_text(json.dumps({"approved_scope_rules": ["https://example.org"]}))
    with pytest.raises(ValueError):
        load_scope(path)


def test_write_feed_is_private_and_rejects_symlink(tmp_path):
    destination = tmp_path / "feed.json"
    write_feed(destination, [])
    assert json.loads(destination.read_text()) == []
    assert destination.stat().st_mode & 0o777 == 0o600
    link = tmp_path / "link.json"
    link.symlink_to(destination)
    with pytest.raises(ValueError, match="symlink"):
        write_feed(link, [])


def test_collector_caps_records():
    # Duplicate CT rows do not inflate output; unique certificate IDs do.
    def fetcher(_query):
        return [row("api.example.org", str(index)) for index in range(600)]
    records = collect_ct_feed(["*.example.org"], fetcher=fetcher)
    assert len(records) == 500
