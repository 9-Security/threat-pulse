from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from .evidence import build_manifest
from .parser import (
    NewsParser,
    ParseError,
    ParsedArticle,
    default_window,
    parse_utc,
    source_key_for_url,
)
from .report import collect_report, render_markdown
from .sources import SOURCES


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="soc-news-parser",
        description="Parse security-news feeds with validated raw-HTML fallbacks.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    sources = subcommands.add_parser("sources", help="list configured sources")
    sources.set_defaults(command="sources")

    article = subcommands.add_parser("article", help="extract one article")
    article.add_argument("url")
    article.add_argument("--title", default="", help="expected article title")
    article.add_argument("--source", choices=sorted(SOURCES))

    audit = subcommands.add_parser(
        "audit", help="extract one article and emit an auditable IoC evidence manifest"
    )
    audit.add_argument("url")
    audit.add_argument("--title", required=True, help="expected article title")
    audit.add_argument("--source", choices=sorted(SOURCES))
    audit.add_argument("--published-at", help="ISO-8601 publication timestamp")
    audit.add_argument("--output", help="write JSON to this path")

    feed = subcommands.add_parser("feed", help="extract recent articles from one feed")
    feed.add_argument("source", choices=sorted(SOURCES))
    feed.add_argument("--hours", type=int, default=24)
    feed.add_argument("--now", help="ISO-8601 UTC window end; defaults to current time")
    feed.add_argument("--limit", type=int)
    feed.add_argument("--output", help="write JSON to this path")

    report = subcommands.add_parser(
        "report", help="collect sources and write auditable JSON and Markdown reports"
    )
    report.add_argument(
        "--source",
        action="append",
        choices=sorted(SOURCES),
        help="source to include; repeat as needed (defaults to all)",
    )
    report.add_argument("--hours", type=int, default=24)
    report.add_argument("--now", help="ISO-8601 UTC window end; defaults to current time")
    report.add_argument("--json-output", required=True)
    report.add_argument("--markdown-output", required=True)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    if args.command == "sources":
        print(
            json.dumps(
                {
                    key: {"name": source.name, "feed_url": source.feed_url}
                    for key, source in SOURCES.items()
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    try:
        with NewsParser() as news_parser:
            if args.command == "report":
                if args.hours <= 0:
                    raise ValueError("--hours must be greater than zero")
                now = parse_utc(args.now) if args.now else None
                since, until = default_window(args.hours, now)
                report = collect_report(
                    news_parser,
                    args.source or list(SOURCES),
                    since=since,
                    until=until,
                )
                rendered = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
                with open(args.json_output, "w", encoding="utf-8") as output:
                    output.write(rendered + "\n")
                with open(args.markdown_output, "w", encoding="utf-8") as output:
                    output.write(render_markdown(report))
                print(
                    json.dumps(
                        {
                            "subject": report.subject,
                            "article_count": report.article_count,
                            "confirmed_ioc_count": report.confirmed_ioc_count,
                            "confirmed_filename_count": report.confirmed_filename_count,
                            "source_failures": len(report.source_failures),
                            "json_output": args.json_output,
                            "markdown_output": args.markdown_output,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
                return
            if args.command in {"article", "audit"}:
                source_key = args.source or source_key_for_url(args.url)
                selectors = SOURCES[source_key].article_selectors if source_key else ()
                body, method, warnings = news_parser.extract_html(
                    args.url, expected_title=args.title, selectors=selectors
                )
                if args.command == "audit":
                    article_source = SOURCES[source_key].name if source_key else "Unknown"
                    published = (
                        parse_utc(args.published_at).isoformat()
                        if args.published_at
                        else None
                    )
                    parsed_article = ParsedArticle(
                        source=article_source,
                        title=args.title,
                        url=args.url,
                        published_at=published,
                        body=body,
                        extraction_method=method,
                        body_characters=len(body),
                        warnings=warnings,
                    )
                    result = build_manifest(parsed_article).to_dict()
                else:
                    result = {
                        "url": args.url,
                        "body": body,
                        "extraction_method": method,
                        "body_characters": len(body),
                        "warnings": warnings,
                    }
            else:
                if args.hours <= 0:
                    raise ValueError("--hours must be greater than zero")
                now: datetime | None = parse_utc(args.now) if args.now else None
                since, until = default_window(args.hours, now)
                result = [
                    article.to_dict()
                    for article in news_parser.parse_feed(
                        SOURCES[args.source],
                        since=since,
                        until=until,
                        limit=args.limit,
                    )
                ]
    except (ParseError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(rendered + "\n")
    else:
        print(rendered)
