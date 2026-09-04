from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from typing import Callable
import time
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
from .analyst import load_previous_iocs, render_ioc_csv_from_actions
from .enrich import (
    EnrichmentReport,
    collect_cve_ids,
    default_fetcher,
    fetcher_for,
    disabled_report,
    enrich_cves,
)
from .report import collect_report, serialize_report
from .resend import ResendClient, ResendError, build_report_email
from .schedule import (
    DEFAULT_CLOCK,
    DEFAULT_TIMEZONE,
    current_slot,
    find_previous_json,
    next_slot,
    report_paths,
    slot_window,
)
from .sources import SOURCES

DEFAULT_CACHE_DIR = ".cache/enrichment"


def _resolve_intel(
    args: argparse.Namespace, report_manifests: list, parser: object | None = None
) -> tuple[dict, object]:
    """Look up KEV/NVD for the day's CVEs. Never fatal: a failure just degrades."""
    if not getattr(args, "enrich", True):
        return {}, disabled_report()
    cve_ids = collect_cve_ids(report_manifests)
    if not cve_ids:
        # Enrichment ran; there was simply nothing to look up.
        return {}, EnrichmentReport(enabled=True)
    close: Callable[[], None] = lambda: None
    if parser is not None:
        fetch = fetcher_for(parser)
    else:
        fetch, close = default_fetcher()
    try:
        return enrich_cves(
            cve_ids,
            fetcher=fetch,
            cache_dir=getattr(args, "cache_dir", DEFAULT_CACHE_DIR),
            api_key=os.environ.get("NVD_API_KEY") or None,
        )
    finally:
        close()


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
    report.add_argument(
        "--csv-output",
        help="optional confirmed IoC CSV for SIEM or block-list import",
    )
    report.add_argument(
        "--previous-json",
        help="yesterday's report JSON; marks new IoCs and adds a day-over-day delta",
    )
    report.add_argument(
        "--no-enrich",
        dest="enrich",
        action="store_false",
        help="skip CISA KEV and NVD lookups; CVSS then comes only from the article",
    )
    report.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        help=f"CVE enrichment cache directory (default {DEFAULT_CACHE_DIR})",
    )

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

    deliver = subcommands.add_parser(
        "deliver",
        help="collect the last 24 hours and email the SOC report",
    )
    deliver.add_argument(
        "--source",
        action="append",
        choices=sorted(SOURCES),
        help="source to include; repeat as needed (defaults to all)",
    )
    deliver.add_argument("--hours", type=int, default=24)
    deliver.add_argument(
        "--at",
        default=DEFAULT_CLOCK,
        help="local send clock HH:MM (default 06:00)",
    )
    deliver.add_argument(
        "--timezone",
        default=DEFAULT_TIMEZONE,
        help="IANA timezone for --at (default Asia/Taipei)",
    )
    deliver.add_argument(
        "--now",
        help="ISO-8601 instant used to choose the most recent send slot",
    )
    deliver.add_argument(
        "--output-dir",
        default="reports",
        help="directory for dated report folders (default reports/)",
    )
    deliver.add_argument(
        "--previous-json",
        help="override yesterday's JSON; defaults to the previous dated folder",
    )
    deliver.add_argument(
        "--to",
        action="append",
        help="recipient; repeat as needed (defaults to comma-separated RESEND_TO)",
    )
    deliver.add_argument(
        "--from",
        dest="sender",
        help="verified sender (defaults to RESEND_FROM)",
    )
    deliver.add_argument(
        "--dry-run",
        action="store_true",
        help="write the report and validate email without calling Resend",
    )
    deliver.add_argument(
        "--no-enrich",
        dest="enrich",
        action="store_false",
        help="skip CISA KEV and NVD lookups; CVSS then comes only from the article",
    )
    deliver.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        help=f"CVE enrichment cache directory (default {DEFAULT_CACHE_DIR})",
    )

    schedule = subcommands.add_parser(
        "schedule",
        help="wait until the daily Taipei slot and deliver the SOC report",
    )
    schedule.add_argument("--hours", type=int, default=24)
    schedule.add_argument("--at", default=DEFAULT_CLOCK)
    schedule.add_argument("--timezone", default=DEFAULT_TIMEZONE)
    schedule.add_argument(
        "--no-enrich",
        dest="enrich",
        action="store_false",
        help="skip CISA KEV and NVD lookups; CVSS then comes only from the article",
    )
    schedule.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        help=f"CVE enrichment cache directory (default {DEFAULT_CACHE_DIR})",
    )
    schedule.add_argument("--output-dir", default="reports")
    schedule.add_argument(
        "--to",
        action="append",
        help="recipient; repeat as needed (defaults to comma-separated RESEND_TO)",
    )
    schedule.add_argument("--from", dest="sender")
    schedule.add_argument(
        "--once",
        action="store_true",
        help="deliver the next slot once, then exit",
    )
    schedule.add_argument(
        "--dry-run",
        action="store_true",
        help="write and validate each slot without calling Resend",
    )
    mcp = subcommands.add_parser(
        "mcp",
        help="run the IoC MCP server (stdio or Streamable HTTP for external agents)",
    )
    mcp.add_argument(
        "--http",
        action="store_true",
        help="serve Streamable HTTP for external LLM / agent clients",
    )
    mcp.add_argument("--host", default="127.0.0.1")
    mcp.add_argument("--port", type=int, default=43124)
    mcp.add_argument("--path", default="/mcp")
    mcp.add_argument(
        "--token",
        help="Bearer token for HTTP mode (defaults to SOC_IOC_MCP_TOKEN)",
    )
    return parser.parse_args()


def _parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[7:].strip()
    if "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    else:
        value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
    return key, value


def _load_workspace_env() -> None:
    env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(line)
        if parsed and parsed[0] not in os.environ:
            os.environ[parsed[0]] = parsed[1]


def _atomic_write(path: str, content: str) -> str:
    destination = Path(path).expanduser().resolve()
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            # The reader digest is taken over the in-memory string, so the bytes
            # on disk must keep its newlines exactly. Without this, Windows
            # writes CRLF and send-report rejects its own report pair.
            newline="\n",
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
    completed: list[tuple[Path, Path | None]] = []
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
                newline="\n",
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
            backup: Path | None = None
            if destination.exists():
                backup = destination.with_name(
                    f".{destination.name}.{os.getpid()}.bak"
                )
                os.replace(destination, backup)
            try:
                os.replace(temporary, destination)
            except OSError:
                if backup and backup.exists():
                    os.replace(backup, destination)
                raise
            completed.append((destination, backup))
        for _, backup in completed:
            if backup and backup.exists():
                backup.unlink()
        return str(json_destination), str(markdown_destination)
    except OSError:
        for destination, backup in reversed(completed):
            if backup and backup.exists():
                os.replace(backup, destination)
        raise
    finally:
        for temporary, _ in staged:
            if temporary.exists():
                temporary.unlink()
        for _, backup in completed:
            if backup and backup.exists():
                backup.unlink()


def _recipients(args: argparse.Namespace) -> list[str]:
    return getattr(args, "to", None) or [
        value.strip()
        for value in os.environ.get("RESEND_TO", "").split(",")
        if value.strip()
    ]


def _sender(args: argparse.Namespace) -> str:
    return getattr(args, "sender", None) or os.environ.get("RESEND_FROM", "")


def _send_report_files(
    *,
    json_path: str,
    markdown_path: str,
    sender: str,
    recipients: list[str],
    dry_run: bool,
) -> dict[str, object]:
    email = build_report_email(
        json_path=json_path,
        markdown_path=markdown_path,
        sender=sender,
        recipients=recipients,
    )
    if dry_run:
        return {
            "dry_run": True,
            "report_id": email.report_id,
            "subject": email.payload["subject"],
            "sender": email.payload["from"],
            "recipients": email.payload["to"],
            "attachment_count": len(email.payload["attachments"]),
            "idempotency_key": email.idempotency_key,
        }
    with ResendClient.from_environment() as resend:
        sent = resend.send(email)
    return {
        "dry_run": False,
        "email_id": sent.email_id,
        "report_id": sent.report_id,
        "idempotency_key": sent.idempotency_key,
    }


def _deliver(args: argparse.Namespace) -> dict[str, object]:
    if args.hours <= 0:
        raise ValueError("--hours must be greater than zero")
    now = parse_utc(args.now) if getattr(args, "now", None) else datetime.now().astimezone()
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    slot = current_slot(now, timezone_name=args.timezone, clock=args.at)
    since, until = slot_window(slot, args.hours)
    json_path, markdown_path, csv_path = report_paths(
        args.output_dir, slot, args.timezone
    )
    json_path.parent.mkdir(parents=True, exist_ok=True)
    previous_path = getattr(args, "previous_json", None) or find_previous_json(
        args.output_dir, slot, args.timezone
    )
    previous_iocs = load_previous_iocs(str(previous_path)) if previous_path else None
    with NewsParser() as news_parser:
        report = collect_report(
            news_parser,
            getattr(args, "source", None) or list(SOURCES),
            since=since,
            until=until,
            generated_at=until,
            previous_iocs=previous_iocs,
            enricher=lambda manifests: _resolve_intel(args, manifests, news_parser),
        )
    json_content, markdown_content = serialize_report(report)
    json_output, markdown_output = _write_report_pair(
        str(json_path),
        str(markdown_path),
        json_content,
        markdown_content,
    )
    csv_output = _atomic_write(
        str(csv_path), render_ioc_csv_from_actions(report.analyst_brief.actions)
    )
    sent = _send_report_files(
        json_path=json_output,
        markdown_path=markdown_output,
        sender=_sender(args),
        recipients=_recipients(args),
        dry_run=bool(getattr(args, "dry_run", False)),
    )
    return {
        "slot": slot.isoformat(),
        "window_start": since.isoformat(),
        "window_end": until.isoformat(),
        "timezone": args.timezone,
        "subject": report.subject,
        "article_count": report.article_count,
        "confirmed_ioc_count": report.confirmed_ioc_count,
        "patch_count": report.analyst_brief.patch_count,
        "block_count": report.analyst_brief.block_count,
        "hunt_count": report.analyst_brief.hunt_count,
        "new_ioc_count": report.analyst_brief.new_ioc_count,
        "previous_json": str(previous_path) if previous_path else None,
        "json_output": json_output,
        "markdown_output": markdown_output,
        "csv_output": csv_output,
        **sent,
    }


def _sleep_until(target: datetime, sleeper: object = time.sleep) -> None:
    while True:
        remaining = (target.astimezone() - datetime.now().astimezone()).total_seconds()
        if remaining <= 0:
            return
        sleeper(min(remaining, 30))  # type: ignore[operator]


def _schedule(args: argparse.Namespace) -> None:
    while True:
        now = datetime.now().astimezone()
        target = next_slot(now, timezone_name=args.timezone, clock=args.at)
        print(
            json.dumps(
                {
                    "waiting_until": target.isoformat(),
                    "timezone": args.timezone,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        _sleep_until(target)
        args.now = target.isoformat()
        try:
            result = _deliver(args)
            print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
        except (ParseError, ResendError, ValueError, OSError) as error:
            print(
                json.dumps(
                    {"error": str(error), "slot": target.isoformat()},
                    ensure_ascii=False,
                ),
                flush=True,
            )
            if args.once:
                raise
        if args.once:
            return


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
        try:
            result = _send_report_files(
                json_path=args.json_report,
                markdown_path=args.markdown_report,
                sender=_sender(args),
                recipients=_recipients(args),
                dry_run=args.dry_run,
            )
        except ResendError as error:
            print(f"error: {error}", file=sys.stderr)
            raise SystemExit(1) from error
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if args.command == "deliver":
        try:
            result = _deliver(args)
        except (ParseError, ResendError, ValueError, OSError) as error:
            print(f"error: {error}", file=sys.stderr)
            raise SystemExit(1) from error
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if args.command == "schedule":
        try:
            _schedule(args)
        except (ParseError, ResendError, ValueError, OSError, KeyboardInterrupt) as error:
            if isinstance(error, KeyboardInterrupt):
                raise SystemExit(130) from error
            print(f"error: {error}", file=sys.stderr)
            raise SystemExit(1) from error
        return
    if args.command == "mcp":
        from .mcp_server import main as run_mcp

        run_mcp(args)
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
                previous_iocs = (
                    load_previous_iocs(args.previous_json)
                    if args.previous_json
                    else None
                )
                report = collect_report(
                    news_parser,
                    args.source or list(SOURCES),
                    since=since,
                    until=until,
                    generated_at=generated_at,
                    previous_iocs=previous_iocs,
                    enricher=lambda manifests: _resolve_intel(args, manifests, news_parser),
                )
                json_content, markdown_content = serialize_report(report)
                json_output, markdown_output = _write_report_pair(
                    args.json_output,
                    args.markdown_output,
                    json_content,
                    markdown_content,
                )
                csv_output = None
                if args.csv_output:
                    csv_output = _atomic_write(
                        args.csv_output,
                        render_ioc_csv_from_actions(report.analyst_brief.actions),
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
                            "confirmed_claim_count": report.confirmed_claim_count,
                            "active_source_count": report.active_source_count,
                            "patch_count": report.analyst_brief.patch_count,
                            "block_count": report.analyst_brief.block_count,
                            "hunt_count": report.analyst_brief.hunt_count,
                            "new_ioc_count": report.analyst_brief.new_ioc_count,
                            "source_failures": len(report.source_failures),
                            "source_warnings": len(report.source_warnings),
                            "json_output": json_output,
                            "markdown_output": markdown_output,
                            "csv_output": csv_output,
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
                    exclude_selectors=(
                        source.exclude_selectors if source else ()
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
