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
    assert {item["hostname"] for item in records} == {"api.example.org"}
    assert all(item["source"] == "crt_sh_ct" for item in records)
    assert all(item["kind"] == "hostname" for item in records)


def test_exact_scope_does_not_expand_to_subdomains():
    records = collect_ct_feed(["example.org"], fetcher=lambda _q: [
        row("example.org\napi.example.org")
    ])
    assert [item["hostname"] for item in records] == ["example.org"]


def test_collector_deduplicates_and_ignores_malformed_rows():
    records = collect_ct_feed(["*.example.org"], fetcher=lambda _q: [
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

from urllib.error import HTTPError

from collect_passive_feed import NoRedirect, _provider_url, fetch_ct_rows


def test_provider_url_is_fixed_https_crt_sh_origin():
    from urllib.parse import urlsplit, parse_qs
    parsed = urlsplit(_provider_url("%.example.org"))
    assert parsed.scheme == "https"
    assert parsed.hostname == "crt.sh"
    assert parsed.path == "/"
    assert parse_qs(parsed.query) == {"q": ["%.example.org"], "output": ["json"]}


def test_redirect_handler_refuses_redirects():
    handler = NoRedirect()
    with pytest.raises(HTTPError):
        handler.redirect_request(__import__("urllib.request").request.Request("https://crt.sh/"), None, 302, "Found", {}, "https://attacker.invalid/")


def test_ct_fetch_rejects_oversized_and_malformed_responses():
    class Response:
        status = 200
        def __init__(self, payload):
            self.payload = payload
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, size=-1):
            return self.payload[:size]
    class Opener:
        def __init__(self, payload):
            self.response = Response(payload)
        def open(self, request, timeout):
            assert timeout == 12
            assert request.full_url.startswith("https://crt.sh/")
            return self.response
    with pytest.raises(ValueError, match="exceeds 2 MiB"):
        fetch_ct_rows("example.org", opener=Opener(b" " * (2 * 1024 * 1024 + 1)))
    with pytest.raises(ValueError, match="invalid JSON"):
        fetch_ct_rows("example.org", opener=Opener(b"not-json"))


from collect_passive_feed import (
    DNSDB_HOST, DNSDB_PATH, DNSDB_QUERY_LIMIT, _dnsdb_url,
    collect_dnsdb_feed, fetch_dnsdb_rows,
)


def dns_row(name="api.example.org.", rrtype="A", rdata=None, timestamp=1760000000):
    return {
        "rrname": name, "rrtype": rrtype,
        "rdata": rdata if rdata is not None else ["192.0.2.10"],
        "time_first": timestamp - 100, "time_last": timestamp,
    }


def test_dnsdb_url_uses_fixed_https_origin_and_wildcard_path():
    from urllib.parse import urlsplit
    url = _dnsdb_url("*.example.org")
    parsed = urlsplit(url)
    assert parsed.scheme == "https"
    assert parsed.hostname == DNSDB_HOST
    assert parsed.path == DNSDB_PATH + "*.example.org"
    assert parsed.query == f"limit={DNSDB_QUERY_LIMIT}"


def test_dnsdb_fetch_parses_saf_ndjson_and_sends_api_key():
    payload = (
        b'{"cond":"begin"}\n'
        b'{"obj":{"rrname":"api.example.org.","rrtype":"A","rdata":["192.0.2.1"]}}\n'
        b'{"cond":"succeeded"}\n'
    )
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=-1): return payload[:size]
    class Opener:
        def open(self, request, timeout):
            assert timeout == 12
            assert request.full_url.startswith(f"https://{DNSDB_HOST}/")
            assert request.get_header("X-Api-Key") == "secret-test-key"
            assert request.get_header("Accept") == "application/x-ndjson"
            return Response()
    rows, completion = fetch_dnsdb_rows("*.example.org", "secret-test-key", opener=Opener())
    assert rows[0]["rrname"] == "api.example.org."
    assert completion == "succeeded"


def test_dnsdb_fetch_rejects_missing_key_incomplete_and_bad_frames():
    with pytest.raises(ValueError, match="API key"):
        fetch_dnsdb_rows("example.org", "")
    class Response:
        status = 200
        def __init__(self, payload): self.payload = payload
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=-1): return self.payload[:size]
    class Opener:
        def __init__(self, payload): self.payload = payload
        def open(self, request, timeout): return Response(self.payload)
    with pytest.raises(ValueError, match="incomplete"):
        fetch_dnsdb_rows("example.org", "key", opener=Opener(b'{"cond":"begin"}\n'))
    with pytest.raises(ValueError, match="invalid SAF object"):
        fetch_dnsdb_rows("example.org", "key", opener=Opener(
            b'{"cond":"begin"}\n{"unexpected":true}\n{"cond":"succeeded"}\n'
        ))


def test_dnsdb_fetch_rejects_oversized_response():
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size=-1): return b"x" * size
    class Opener:
        def open(self, request, timeout): return Response()
    with pytest.raises(ValueError, match="exceeds 1 MiB"):
        fetch_dnsdb_rows("example.org", "key", opener=Opener())


def test_dnsdb_collector_scope_filters_and_excludes_zone_only_rows():
    calls = []
    def fetcher(query, key):
        calls.append((query, key))
        return [
            dns_row(),
            dns_row("api.example.org.", rdata=["192.0.2.10"]),
            dns_row("outside.invalid."),
            {"rrname": "zone.example.org.", "rrtype": "A", "rdata": ["192.0.2.5"],
             "zone_time_last": 1760000000},
            dns_row("bad.example.org.", rrtype="A/IN"),
        ], "succeeded"
    records = collect_dnsdb_feed(["*.example.org"], "key", fetcher=fetcher)
    assert calls == [("*.example.org", "key")]
    assert len(records) == 1
    assert records[0]["hostname"] == "api.example.org"
    assert records[0]["kind"] == "dns_record"
    assert records[0]["source"] == "dnsdb_passive_dns"
    assert "hostname=api.example.org" in records[0]["evidence"]


def test_dnsdb_collector_exact_scope_does_not_expand():
    records = collect_dnsdb_feed(["example.org"], "key", fetcher=lambda q, k: (
        [dns_row("example.org."), dns_row("api.example.org.")], "limited"
    ))
    assert [record["hostname"] for record in records] == ["example.org"]


def test_dnsdb_collector_rejects_invalid_rrdata_and_dates():
    records = collect_dnsdb_feed(["*.example.org"], "key", fetcher=lambda q, k: (
        [dns_row("api.example.org.", rdata=["valid", "bad\nvalue"]),
         dns_row("badtime.example.org.", timestamp=10**30)], "succeeded"
    ))
    assert len(records) == 1


def test_dnsdb_query_builder_rejects_path_injection():
    with pytest.raises(ValueError):
        _dnsdb_url("example.org/../../attacker.invalid")


def test_dnsdb_collector_skips_non_object_provider_rows():
    records = collect_dnsdb_feed(["*.example.org"], "key", fetcher=lambda q, k: (
        [None, dns_row()], "succeeded"
    ))
    assert len(records) == 1
