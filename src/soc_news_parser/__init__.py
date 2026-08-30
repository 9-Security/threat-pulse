from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from .evidence import build_manifest
from .parser import (
    NewsParser,
    ParseError,
    ParsedArticle,
    default_window,
    parse_utc,
    source_key_for_url,
)
from .report import collect_report, serialize_report
from .resend import ResendClient, ResendError, build_report_email
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
    report.add_argument(
        "--generated-at",
        help="ISO-8601 generation timestamp for reproducible output",
    )
    report.add_argument("--json-output", required=True)
    report.add_argument("--markdown-output", required=True)

    send_report = subcommands.add_parser(
        "send-report", help="send a verified JSON/Markdown report pair using Resend"
    )
    send_report.add_argument("--json-report", required=True)
    send_report.add_argument("--markdown-report", required=True)
    send_report.add_argument(
        "--to",
        action="append",
        help="recipient; repeat as needed (defaults to comma-separated RESEND_TO)",
    )
    send_report.add_argument(
        "--from",
        dest="sender",
        help="verified sender (defaults to RESEND_FROM)",
    )
    send_report.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and summarize without calling Resend",
    )
    return parser.parse_args()


def _load_workspace_env() -> None:
    env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def _atomic_write(path: str, content: str) -> str:
    destination = Path(path).expanduser().resolve()
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        return str(destination)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def _write_report_pair(
    json_path: str, markdown_path: str, json_content: str, markdown_content: str
) -> tuple[str, str]:
    json_destination = Path(json_path).expanduser().resolve()
    markdown_destination = Path(markdown_path).expanduser().resolve()
    if json_destination == markdown_destination:
        raise ValueError("JSON and Markdown output paths must be different")

    staged: list[tuple[Path, Path]] = []
    try:
        for destination, content in (
            (json_destination, json_content),
            (markdown_destination, markdown_content),
        ):
            if not destination.parent.is_dir():
                raise OSError(f"output directory does not exist: {destination.parent}")
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                delete=False,
            ) as output:
                temporary = Path(output.name)
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            staged.append((temporary, destination))
        for temporary, destination in staged:
            os.replace(temporary, destination)
        return str(json_destination), str(markdown_destination)
    finally:
        for temporary, _ in staged:
            if temporary.exists():
                temporary.unlink()


def main() -> None:
    args = _arguments()
    _load_workspace_env()
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
    if args.command == "send-report":
        recipients = args.to or [
            value.strip()
            for value in os.environ.get("RESEND_TO", "").split(",")
            if value.strip()
        ]
        sender = args.sender or os.environ.get("RESEND_FROM", "")
        try:
            email = build_report_email(
                json_path=args.json_report,
                markdown_path=args.markdown_report,
                sender=sender,
                recipients=recipients,
            )
            if args.dry_run:
                result = {
                    "dry_run": True,
                    "report_id": email.report_id,
                    "subject": email.payload["subject"],
                    "sender": email.payload["from"],
                    "recipients": email.payload["to"],
                    "attachment_count": len(email.payload["attachments"]),
                    "idempotency_key": email.idempotency_key,
                }
            else:
                with ResendClient.from_environment() as resend:
                    sent = resend.send(email)
                result = {
                    "dry_run": False,
                    "email_id": sent.email_id,
                    "report_id": sent.report_id,
                    "idempotency_key": sent.idempotency_key,
                }
        except ResendError as error:
            print(f"error: {error}", file=sys.stderr)
            raise SystemExit(1) from error
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    try:
        with NewsParser() as news_parser:
            if args.command == "report":
                if args.hours <= 0:
                    raise ValueError("--hours must be greater than zero")
                now = parse_utc(args.now) if args.now else None
                since, until = default_window(args.hours, now)
                generated_at = (
                    parse_utc(args.generated_at) if args.generated_at else None
                )
                report = collect_report(
                    news_parser,
                    args.source or list(SOURCES),
                    since=since,
                    until=until,
                    generated_at=generated_at,
                )
                json_content, markdown_content = serialize_report(report)
                json_output, markdown_output = _write_report_pair(
                    args.json_output,
                    args.markdown_output,
                    json_content,
                    markdown_content,
                )
                print(
                    json.dumps(
                        {
                            "subject": report.subject,
                            "report_id": report.report_id,
                            "sources_checked": len(report.sources_checked),
                            "collected_article_count": report.collected_article_count,
                            "article_count": report.article_count,
                            "excluded_article_count": report.excluded_article_count,
                            "confirmed_ioc_count": report.confirmed_ioc_count,
                            "confirmed_filename_count": report.confirmed_filename_count,
                            "source_failures": len(report.source_failures),
                            "source_warnings": len(report.source_warnings),
                            "json_output": json_output,
                            "markdown_output": markdown_output,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
                return
            if args.command in {"article", "audit"}:
                source_key = args.source or source_key_for_url(args.url)
                source = SOURCES[source_key] if source_key else None
                selectors = source.article_selectors if source else ()
                allowed_hosts = source.article_hosts if source else ()
                body, method, warnings = news_parser.extract_html(
                    args.url,
                    expected_title=args.title,
                    selectors=selectors,
                    allowed_hosts=allowed_hosts,
                    min_body_characters=(
                        source.min_body_characters if source else 500
                    ),
                )
                if args.command == "audit":
                    article_source = source.name if source else "Unknown"
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
                        publisher_hosts=source.article_hosts if source else (),
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
        _atomic_write(args.output, rendered + "\n")
    else:
        print(rendered)
