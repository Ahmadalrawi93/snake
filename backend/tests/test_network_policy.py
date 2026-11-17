import pytest

from app.core.network_policy import (
    NetworkPolicyError,
    resolve_public_destination,
    validate_redirect_chain,
)


def fake_resolver(records):
    def resolve(hostname, port):
        return records.get(hostname, [])
    return resolve


def test_public_dns_answer_is_returned_for_pinning():
    result = resolve_public_destination(
        "https://example.com/path", ["example.com"],
        fake_resolver({"example.com": ["93.184.216.34"]}),
    )
    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.addresses == ("93.184.216.34",)


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.1.1", "::1", "fc00::1", "fe80::1", "224.0.0.1",
])
def test_private_or_special_addresses_are_rejected(address):
    with pytest.raises(NetworkPolicyError):
        resolve_public_destination(
            "https://example.com", ["example.com"],
            fake_resolver({"example.com": [address]}),
        )


def test_mixed_public_and_private_dns_answer_is_rejected():
    with pytest.raises(NetworkPolicyError, match="non_public_ip_address"):
        resolve_public_destination(
            "https://example.com", ["example.com"],
            fake_resolver({"example.com": ["93.184.216.34", "127.0.0.1"]}),
        )


def test_empty_dns_answer_is_rejected():
    with pytest.raises(NetworkPolicyError, match="dns_no_addresses"):
        resolve_public_destination(
            "https://example.com", ["example.com"], fake_resolver({})
        )


def test_ip_literal_must_be_in_scope_and_public():
    result = resolve_public_destination("https://93.184.216.34", ["93.184.216.34"])
    assert result.addresses == ("93.184.216.34",)
    with pytest.raises(NetworkPolicyError):
        resolve_public_destination("http://127.0.0.1", ["127.0.0.1"])


def test_out_of_scope_redirect_is_rejected():
    resolver = fake_resolver({"example.com": ["93.184.216.34"], "evil.test": ["8.8.8.8"]})
    with pytest.raises(NetworkPolicyError, match="out_of_scope"):
        validate_redirect_chain(
            "https://example.com", ["https://evil.test"], ["example.com"], resolver
        )


def test_each_redirect_is_resolved_and_pinned_independently():
    resolver = fake_resolver({
        "example.com": ["93.184.216.34"],
        "cdn.example.com": ["1.1.1.1"],
    })
    result = validate_redirect_chain(
        "https://example.com", ["https://cdn.example.com/a"],
        ["example.com", "*.example.com"], resolver,
    )
    assert [item.addresses for item in result] == [
        ("93.184.216.34",), ("1.1.1.1",)
    ]


def test_credentials_and_non_http_redirects_are_rejected():
    with pytest.raises(NetworkPolicyError):
        resolve_public_destination("https://user:pass@example.com", ["example.com"])
    with pytest.raises(NetworkPolicyError):
        resolve_public_destination("file:///etc/passwd", ["example.com"])
