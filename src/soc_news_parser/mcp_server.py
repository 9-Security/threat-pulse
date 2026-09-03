from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from .ioc_query import (
    list_report_dates,
    lookup_indicator,
    report_summary,
    search_iocs,
)


def build_server() -> MCPServer:
    server = MCPServer(
        name="iocs",
        title="SOC IoC reports",
        instructions=(
            "Query confirmed IoCs and analyst actions from local dated "
            "SOC report JSON under reports/YYYY-MM-DD/. Does not scrape "
            "the live web; run soc-news-parser deliver first."
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

    return server


def main() -> None:
    build_server().run(transport="stdio")
