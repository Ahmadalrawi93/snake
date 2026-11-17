from app.core.scope_policy import ScopePolicy, host_matches, normalize_host


def test_exact_match():
    assert ScopePolicy(["example.com"]).check_url("https://example.com").allowed


def test_wildcard_matches_subdomain_only():
    policy = ScopePolicy(["*.example.com"])
    assert policy.check_url("https://api.example.com").allowed
    assert not policy.check_url("https://example.com").allowed


def test_lookalike_is_rejected():
    assert not ScopePolicy(["example.com"]).check_url("https://example.com.attacker.test").allowed


def test_non_http_scheme_is_rejected():
    assert not ScopePolicy(["example.com"]).check_url("ftp://example.com").allowed


def test_url_credentials_are_rejected():
    result = ScopePolicy(["example.com"]).check_url("https://user:pass@example.com")
    assert not result.allowed
    assert result.reason == "embedded_credentials_not_allowed"


def test_host_normalization():
    assert normalize_host("EXAMPLE.COM.") == "example.com"


def test_invalid_hostname_is_rejected():
    try:
        normalize_host("bad host")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected invalid hostname")

def test_malformed_port_is_rejected():
    result = ScopePolicy(["example.com"]).check_url("https://example.com:99999")
    assert not result.allowed

def test_invalid_ipv6_authority_is_rejected():
    result = ScopePolicy(["example.com"]).check_url("https://[not-ipv6]/")
    assert not result.allowed
