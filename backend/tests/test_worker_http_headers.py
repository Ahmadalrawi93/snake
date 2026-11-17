from email.message import Message

import pytest

from worker_https_server import MAX_BODY_BYTES, validate_http_task_headers


def _headers(*, content_length="2", content_type="application/json", host="worker.example"):
    headers = Message()
    if content_length is not None:
        headers["Content-Length"] = content_length
    if content_type is not None:
        headers["Content-Type"] = content_type
    if host is not None:
        headers["Host"] = host
    return headers


def test_accepts_unambiguous_json_request_headers():
    assert validate_http_task_headers(_headers()) == (200, 2)


@pytest.mark.parametrize("name,value", [
    ("Content-Length", "3"),
    ("Content-Type", "text/plain"),
    ("Host", "attacker.example"),
])
def test_rejects_duplicate_framing_or_routing_headers(name, value):
    headers = _headers()
    headers[name] = value
    assert validate_http_task_headers(headers) == (400, None)


def test_rejects_transfer_encoding_even_with_content_length():
    headers = _headers()
    headers["Transfer-Encoding"] = "chunked"
    assert validate_http_task_headers(headers) == (400, None)


def test_rejects_expect_continue():
    headers = _headers()
    headers["Expect"] = "100-continue"
    assert validate_http_task_headers(headers) == (417, None)


def test_requires_exact_application_json_content_type():
    assert validate_http_task_headers(_headers(content_type=None)) == (415, None)
    assert validate_http_task_headers(_headers(content_type="application/json; charset=utf-8")) == (415, None)


def test_requires_content_length():
    assert validate_http_task_headers(_headers(content_length=None)) == (411, None)


@pytest.mark.parametrize("value", ["", "+2", "-1", "2.0", "２", "abc"])
def test_rejects_non_ascii_decimal_content_length(value):
    assert validate_http_task_headers(_headers(content_length=value)) == (400, None)


def test_rejects_zero_and_oversized_content_length():
    assert validate_http_task_headers(_headers(content_length="0")) == (413, None)
    assert validate_http_task_headers(_headers(content_length=str(MAX_BODY_BYTES + 1))) == (413, None)
