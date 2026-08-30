from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from .parser import NewsParser, ParseError, default_window, parse_utc, source_key_for_url
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

    feed = subcommands.add_parser("feed", help="extract recent articles from one feed")
    feed.add_argument("source", choices=sorted(SOURCES))
    feed.add_argument("--hours", type=int, default=24)
    feed.add_argument("--now", help="ISO-8601 UTC window end; defaults to current time")
    feed.add_argument("--limit", type=int)
    feed.add_argument("--output", help="write JSON to this path")
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
            if args.command == "article":
                source_key = args.source or source_key_for_url(args.url)
                selectors = SOURCES[source_key].article_selectors if source_key else ()
                body, method, warnings = news_parser.extract_html(
                    args.url, expected_title=args.title, selectors=selectors
                )
                result: object = {
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
