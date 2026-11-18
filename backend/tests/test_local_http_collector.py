from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from app.core.local_http_collector import collect_http


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'<html><a href="/about">about</a><a href="http://example.com/out">out</a></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "lab/1.2.3")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/about":
            body = b"about"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.com/escape")
            self.end_headers()
        elif self.path == "/cookie":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "session=super-secret-value; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/large":
            body = b"x" * 4096
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_collector_follows_only_same_host_links(local_server):
    report = collect_http(
        local_server,
        ["127.0.0.1"],
        max_pages=5,
        allow_private_networks=True,
        allow_nonstandard_ports=True,
    )
    assert [item.status_code for item in report.observations] == [200, 200]
    assert report.pages_requested == 2
    assert all("example.com" not in item.url for item in report.observations)


def test_collector_refuses_non_public_dns_by_default(local_server):
    report = collect_http(local_server, ["127.0.0.1"], max_pages=1, allow_nonstandard_ports=True)
    assert report.pages_requested == 0
    assert report.skipped[0][1] == "dns_resolved_to_non_public_address"


def test_collector_does_not_follow_out_of_scope_redirect(local_server):
    report = collect_http(
        local_server + "/redirect",
        ["127.0.0.1"],
        max_pages=3,
        allow_private_networks=True,
        allow_nonstandard_ports=True,
    )
    assert len(report.observations) == 1
    assert report.observations[0].status_code == 302
    assert report.skipped == (("http://example.com/escape", "cross_origin_redirect_skipped"),)


def test_collector_caps_response_body(local_server):
    report = collect_http(
        local_server + "/large",
        ["127.0.0.1"],
        max_pages=1,
        max_body_bytes=1024,
        allow_private_networks=True,
        allow_nonstandard_ports=True,
    )
    assert report.pages_requested == 1
    assert report.observations[0].body_bytes == 1024


@pytest.mark.parametrize("value", [0, 11])
def test_collector_rejects_invalid_timeout(value):
    with pytest.raises(ValueError):
        collect_http("https://example.com", ["example.com"], timeout=value)


def test_collector_redacts_cookie_values(local_server):
    report = collect_http(
        local_server + "/cookie",
        ["127.0.0.1"],
        max_pages=1,
        allow_private_networks=True,
        allow_nonstandard_ports=True,
    )
    cookie = next(value for name, value in report.observations[0].headers if name == "set-cookie")
    assert cookie == "session=<redacted>; HttpOnly"
    assert "super-secret-value" not in cookie


def test_collector_rejects_nonstandard_ports_by_default():
    from app.core.local_http_collector import CollectionError

    with pytest.raises(CollectionError, match="unsupported_target_port"):
        collect_http("https://example.com:8443", ["example.com"], max_pages=1)
