"""Small ASGI security middleware for the SNAKE API edge."""

from __future__ import annotations

from typing import Any


class _BodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies, including chunked bodies without Content-Length."""

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                declared_length = int(raw_length)
            except (TypeError, ValueError):
                await self._reject(send, 400, b'{"detail":"Invalid Content-Length"}')
                return
            if declared_length < 0:
                await self._reject(send, 400, b'{"detail":"Invalid Content-Length"}')
                return
            if declared_length > self.max_bytes:
                await self._reject(send, 413, b'{"detail":"Request body too large"}')
                return

        received = 0

        async def limited_receive() -> dict:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await self._reject(send, 413, b'{"detail":"Request body too large"}')

    @staticmethod
    async def _reject(send: Any, status_code: int, body: bytes) -> None:
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ],
        })
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    """Apply conservative headers to API responses; HSTS only in production."""

    def __init__(self, app: Any, production: bool = False) -> None:
        self.app = app
        self.production = production

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secured_send(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {key.lower() for key, _ in headers}
                additions = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
                ]
                if self.production:
                    additions.append((b"strict-transport-security", b"max-age=63072000; includeSubDomains"))
                for key, value in additions:
                    if key not in present:
                        headers.append((key, value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, secured_send)
