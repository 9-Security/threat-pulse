from __future__ import annotations

import asyncio

import pytest
from starlette.responses import JSONResponse

from soc_news_parser.mcp_server import (
    BearerAuthMiddleware,
    bearer_token_matches,
    require_http_token,
)


class _DummyApp:
    def __init__(self) -> None:
        self.called = False

    async def __call__(self, scope, receive, send) -> None:
        self.called = True
        response = JSONResponse({"ok": True})
        await response(scope, receive, send)


async def _collect(app, path: str, authorization: str | None = None) -> tuple[int, bytes]:
    headers = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 123),
        "server": ("127.0.0.1", 80),
    }
    messages: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app(scope, receive, send)
    start = next(item for item in messages if item["type"] == "http.response.start")
    body = b"".join(
        item.get("body", b"")
        for item in messages
        if item["type"] == "http.response.body"
    )
    return int(start["status"]), body


def test_bearer_compare_rejects_wrong_or_missing_token() -> None:
    assert bearer_token_matches("Bearer secret-token", "secret-token")
    assert not bearer_token_matches("Bearer secret-token", "other-token")
    assert not bearer_token_matches("secret-token", "secret-token")
    assert not bearer_token_matches("", "secret-token")


def test_http_mode_requires_token() -> None:
    with pytest.raises(ValueError, match="SOC_IOC_MCP_TOKEN"):
        require_http_token("")


def test_middleware_allows_health_without_token() -> None:
    inner = _DummyApp()
    app = BearerAuthMiddleware(inner, "secret-token")
    status, body = asyncio.run(_collect(app, "/health"))
    assert status == 200
    assert b'"ok":true' in body.replace(b" ", b"")
    assert inner.called is True


def test_middleware_rejects_mcp_without_bearer() -> None:
    inner = _DummyApp()
    app = BearerAuthMiddleware(inner, "secret-token")
    status, body = asyncio.run(_collect(app, "/mcp"))
    assert status == 401
    assert b"unauthorized" in body
    assert inner.called is False


def test_middleware_accepts_matching_bearer() -> None:
    inner = _DummyApp()
    app = BearerAuthMiddleware(inner, "secret-token")
    status, _ = asyncio.run(_collect(app, "/mcp", "Bearer secret-token"))
    assert status == 200
    assert inner.called is True
