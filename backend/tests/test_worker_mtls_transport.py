import ssl
import pytest

from app.core.worker_mtls_transport import (
    _PinnedHTTPSConnection,
    _build_mtls_context,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
)


def test_pinned_connection_keeps_dns_name_for_tls_identity():
    context = ssl.create_default_context()
    connection = _PinnedHTTPSConnection(
        pinned_ip="93.184.216.34",
        hostname="worker.example.org",
        port=443,
        context=context,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        expected_fingerprint="a" * 64,
    )
    assert connection.host == "worker.example.org"
    assert connection.port == 443
    assert connection._pinned_ip == "93.184.216.34"
    assert connection._expected_fingerprint == "a" * 64
    connection.close()


def test_mtls_context_requires_both_client_credentials():
    with pytest.raises(ValueError, match="mTLS client certificate"):
        _build_mtls_context("", "", "")


def test_response_limit_is_bounded():
    assert MAX_RESPONSE_BYTES == 64 * 1024
