import asyncio

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.http_security import RequestBodyLimitMiddleware, SecurityHeadersMiddleware


def test_security_headers_are_applied_and_hsts_is_production_only():
    app = FastAPI()

    @app.get("/")
    def root():
        return {"ok": True}

    app.add_middleware(SecurityHeadersMiddleware, production=False)
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "content-security-policy" not in response.headers
    assert "strict-transport-security" not in response.headers

    production_app = FastAPI()
    production_app.add_middleware(SecurityHeadersMiddleware, production=True)
    production_response = TestClient(production_app).get("/")
    assert production_response.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"
    assert "default-src 'none'" in production_response.headers["content-security-policy"]
    assert "default-src 'none'" in production_response.headers["content-security-policy"]


def test_request_body_limit_rejects_declared_oversized_body():
    async def app(scope, receive, send):
        raise AssertionError("Oversized request must be rejected before application dispatch")

    wrapped = RequestBodyLimitMiddleware(app, max_bytes=8)
    response_messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        response_messages.append(message)

    asyncio.run(wrapped(
        {"type": "http", "method": "POST", "path": "/", "headers": [(b"content-length", b"9")]},
        receive,
        send,
    ))
    assert response_messages[0]["status"] == 413
    assert b"Request body too large" in response_messages[1]["body"]


def test_request_body_limit_rejects_chunked_body_without_content_length():
    async def app(scope, receive, send):
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    wrapped = RequestBodyLimitMiddleware(app, max_bytes=5)
    response_messages = []
    chunks = iter([
        {"type": "http.request", "body": b"123", "more_body": True},
        {"type": "http.request", "body": b"456", "more_body": False},
    ])

    async def receive():
        return next(chunks)

    async def send(message):
        response_messages.append(message)

    asyncio.run(wrapped(
        {"type": "http", "method": "POST", "path": "/", "headers": []},
        receive,
        send,
    ))
    assert response_messages[0]["status"] == 413
    assert b"Request body too large" in response_messages[1]["body"]


def test_trusted_host_middleware_rejects_unlisted_host_header():
    app = FastAPI()

    @app.get("/")
    def root():
        return {"ok": True}

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.example.com"])
    client = TestClient(app)
    denied = client.get("/", headers={"Host": "attacker.example"})
    assert denied.status_code == 400
    accepted = client.get("/", headers={"Host": "api.example.com"})
    assert accepted.status_code == 200
