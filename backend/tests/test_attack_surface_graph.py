from attack_surface_graph import build_attack_surface_graph


def test_graph_links_url_to_hostname_and_scope_and_marks_api_hint():
    records = [{
        "hostname": "api.example.org", "kind": "url",
        "value": "https://api.example.org/v1/users",
        "source": "ct_passive", "observed_at": "2026-11-17T10:00:00+00:00",
    }]
    graph = build_attack_surface_graph(records, ["example.org"])
    types = {node["type"] for node in graph["nodes"]}
    relations = {edge["relation"] for edge in graph["edges"]}
    assert {"hostname", "scope_rule", "url", "api_route_hint"} <= types
    assert "matches_approved_scope_rule" in relations
    assert "observed_on_hostname" in relations
    assert "passive_api_path_hint" in relations
    assert graph["execution_enabled"] is False


def test_graph_excludes_out_of_scope_and_host_mismatch_urls():
    records = [
        {"hostname": "evil.test", "kind": "url", "value": "https://evil.test/api",
         "source": "x", "observed_at": "2026-11-17T00:00:00+00:00"},
        {"hostname": "api.example.org", "kind": "url", "value": "https://other.example.org/api",
         "source": "x", "observed_at": "2026-11-17T00:00:00+00:00"},
    ]
    graph = build_attack_surface_graph(records, ["example.org"])
    assert graph["summary"]["nodes"] == 2
    assert graph["summary"]["api_route_hints"] == 0


def test_graph_deduplicates_nodes_and_merges_evidence_sources():
    records = []
    for source in ("ct", "dnsdb"):
        records.append({"hostname": "api.example.org", "kind": "url",
                        "value": "https://api.example.org/graphql",
                        "source": source, "observed_at": "2026-11-17T00:00:00+00:00"})
    graph = build_attack_surface_graph(records, ["example.org"])
    assert len([n for n in graph["nodes"] if n["type"] == "url"]) == 1
    api_edge = next(e for e in graph["edges"] if e["relation"] == "passive_api_path_hint")
    assert {e["source"] for e in api_edge["evidence"]} == {"ct", "dnsdb"}


def test_graph_rejects_oversized_input():
    import pytest
    with pytest.raises(ValueError):
        build_attack_surface_graph([{}] * 501, ["example.org"])
