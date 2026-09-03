from __future__ import annotations

import argparse
import hmac
import os
from typing import Any

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

from .ioc_query import (
    list_report_dates,
    lookup_indicator,
    report_summary,
    search_iocs,
)

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 43124
DEFAULT_HTTP_PATH = "/mcp"


class BearerAuthMiddleware:
    """Require Authorization: Bearer <token> on every HTTP path except /health."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path") or "")
        if path == "/health" or path.endswith("/health"):
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers") or []
        }
        if not bearer_token_matches(headers.get("authorization", ""), self.token):
            response = JSONResponse({"error": "unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def bearer_token_matches(authorization: str, expected: str) -> bool:
    if not expected or not authorization.startswith("Bearer "):
        return False
    provided = authorization[7:]
    if len(provided) != len(expected):
        return False
    return hmac.compare_digest(provided, expected)


def resolve_http_token(explicit: str | None = None) -> str:
    return (explicit or os.environ.get("SOC_IOC_MCP_TOKEN") or "").strip()


def require_http_token(token: str) -> str:
    if not token:
        raise ValueError(
            "HTTP MCP requires a bearer token via --token or SOC_IOC_MCP_TOKEN"
        )
    return token


def add_mcp_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--http",
        action="store_true",
        help="serve Streamable HTTP for external LLM / agent clients",
    )
    parser.add_argument("--host", default=DEFAULT_HTTP_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--path", default=DEFAULT_HTTP_PATH)
    parser.add_argument(
        "--token",
        help="Bearer token for HTTP mode (defaults to SOC_IOC_MCP_TOKEN)",
    )


def build_server() -> MCPServer:
    server = MCPServer(
        name="iocs",
        title="SOC IoC reports",
        instructions=(
            "Query confirmed IoCs and analyst actions from local dated "
            "SOC report JSON under reports/YYYY-MM-DD/. Does not scrape "
            "the live web; run soc-news-parser deliver first. Remote HTTP "
            "clients must send Authorization: Bearer <token>."
        ),
        log_level="WARNING",
    )

    @server.tool(description="List dated SOC IoC reports on disk, newest first.")
    def list_reports() -> dict[str, Any]:
        items = list_report_dates()
        return {"count": len(items), "reports": items}

    @server.tool(
        description="Summarize one report: subject, window, and patch/block/hunt counts."
    )
    def get_report_summary(date: str | None = None) -> dict[str, Any]:
        return report_summary(date)

    @server.tool(
        description=(
            "Search confirmed IoCs in a report. Optional filters: query text, "
            "analyst action (patch/block/hunt), indicator_type (cve/domain/ip/url/sha256/...)."
        )
    )
    def search_confirmed_iocs(
        query: str = "",
        date: str | None = None,
        action: str | None = None,
        indicator_type: str | None = None,
        limit: int = 40,
    ) -> dict[str, Any]:
        return search_iocs(
            query,
            date=date,
            action=action,
            indicator_type=indicator_type,
            limit=limit,
        )

    @server.tool(
        description="Look up one indicator by exact normalized or raw value in a report."
    )
    def lookup_ioc(value: str, date: str | None = None) -> dict[str, Any]:
        return lookup_indicator(value, date=date)

    @server.custom_route("/health", methods=["GET"])
    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "server": "iocs"})

    return server


def build_http_app(token: str, *, host: str, path: str) -> Any:
    token = require_http_token(token)
    server = build_server()
    app = server.streamable_http_app(
        streamable_http_path=path,
        stateless_http=True,
        host=host,
    )
    return BearerAuthMiddleware(app, token)


def run_http(host: str, port: int, path: str, token: str) -> None:
    import uvicorn

    app = build_http_app(token, host=host, path=path)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    uvicorn.Server(config).run()


def main(args: argparse.Namespace | None = None) -> None:
    if args is None:
        parser = argparse.ArgumentParser(prog="soc-iocs-mcp")
        add_mcp_arguments(parser)
        args = parser.parse_args()
    if getattr(args, "http", False):
        token = require_http_token(resolve_http_token(getattr(args, "token", None)))
        run_http(
            host=getattr(args, "host", DEFAULT_HTTP_HOST),
            port=int(getattr(args, "port", DEFAULT_HTTP_PORT)),
            path=getattr(args, "path", DEFAULT_HTTP_PATH),
            token=token,
        )
        return
    build_server().run(transport="stdio")
