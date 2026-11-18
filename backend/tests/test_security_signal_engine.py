from app.core.security_signal_engine import analyze_security_signals


def obs(oid, kind, value, host="app.example.test"):
    return {
        "observation_id": oid,
        "kind": kind,
        "value": value,
        "host_key": host,
    }


def test_detects_cors_wildcard_with_credentials_as_validation_lead():
    report = analyze_security_signals([
        obs("o1", "http_header", "Access-Control-Allow-Origin: *"),
        obs("o2", "http_header", "Access-Control-Allow-Credentials: true"),
    ])
    assert report.signal_count == 1
    signal = report.signals[0]
    assert signal.category == "cors_configuration"
    assert signal.confidence == "medium"
    assert signal.disposition == "requires_validation"
    assert signal.severity == "not_assessed"
    assert set(signal.evidence_observation_ids) == {"o1", "o2"}


def test_cookie_signal_never_contains_cookie_value():
    report = analyze_security_signals([
        obs("cookie-1", "http_header", "Set-Cookie: session=TOP_SECRET; Path=/")
    ])
    assert report.signal_count == 1
    signal = report.signals[0]
    assert "session" in signal.title
    assert "TOP_SECRET" not in signal.model_dump_json()
    assert "secure" in signal.rationale.lower()
    assert signal.severity == "not_assessed"


def test_detects_version_disclosure_and_does_not_call_it_vulnerable():
    report = analyze_security_signals([
        obs("server-1", "http_header", "Server: nginx/1.18.0")
    ])
    assert report.signal_count == 1
    assert report.signals[0].category == "technology_disclosure"
    assert "not_assessed" == report.signals[0].severity


def test_url_path_signals_are_unverified_and_http_is_separate():
    report = analyze_security_signals([
        obs("url-1", "url", "http://app.example.test/.git/config"),
        obs("url-2", "url", "https://app.example.test/backups/db.sql")
    ])
    categories = {item.category for item in report.signals}
    assert categories == {"transport_security", "possible_git_metadata", "possible_backup_file"}
    assert all("not proof" in item.rationale.lower() or item.category == "transport_security"
               for item in report.signals)


def test_no_signal_for_unobserved_missing_headers_or_route_names():
    report = analyze_security_signals([
        obs("url-1", "url", "https://app.example.test/login"),
        obs("tech-1", "technology", "nginx")
    ])
    assert report.signals == []
    assert report.source_observation_count == 2


def test_signals_are_stable_and_bounded():
    observations = [
        obs("o1", "http_header", "X-Powered-By: PHP/8.2"),
        obs("o2", "http_header", "Server: nginx/1.20"),
    ]
    first = analyze_security_signals(observations)
    second = analyze_security_signals(observations)
    assert [x.signal_id for x in first.signals] == [x.signal_id for x in second.signals]
    assert analyze_security_signals(observations, max_signals=1).signal_count == 1
