from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit

from .evidence import Evidence, EvidenceManifest, build_manifest
from .parser import NewsParser, ParseError
from .sources import SOURCES


REPORT_SCHEMA_VERSION = "1.1"
COUNTED_IOC_TYPES = frozenset({"md5", "sha1", "sha256", "ip", "domain", "url"})
TOPIC_RE = re.compile(
    r"\b(?:cyber|security|malware|ransomware|phishing|vulnerability|cve-\d|"
    r"exploit|attack|breach|threat|apt|backdoor|botnet|zero-day|0-day|"
    r"privacy|tracking|credential|remote code execution|rce|data exposure|"
    r"incident response|ioc)\b|"
    r"(?:資安|網路攻擊|惡意程式|勒索軟體|漏洞|資料外洩|釣魚|威脅|入侵|隱私)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SourceFailure:
    source_key: str
    source_name: str
    error: str


@dataclass(frozen=True)
class SourceWarning:
    source_key: str
    source_name: str
    warning: str


@dataclass(frozen=True)
class DailyReport:
    schema_version: str
    report_id: str
    window_start: str
    window_end: str
    generated_at: str
    sources_checked: list[str]
    collected_article_count: int
    article_count: int
    excluded_article_count: int
    confirmed_ioc_count: int
    confirmed_filename_count: int
    count_policy: str
    articles: list[EvidenceManifest]
    excluded_articles: list[EvidenceManifest]
    source_failures: list[SourceFailure]
    source_warnings: list[SourceWarning]

    @property
    def subject(self) -> str:
        return (
            "[SOC] 每日資安新聞 IoC 彙整報告 - "
            f"文章數 {self.article_count} / IoC數 {self.confirmed_ioc_count}"
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["subject"] = self.subject
        return result


def _unique_confirmed(
    manifests: Iterable[EvidenceManifest], accepted_types: frozenset[str]
) -> set[tuple[str, str]]:
    return {
        (evidence.indicator_type, evidence.normalized_value)
        for manifest in manifests
        for evidence in manifest.evidence
        if evidence.status == "confirmed"
        and evidence.indicator_type in accepted_types
    }


_SENTENCE_ENDINGS = ".!?。！？"


def _last_sentence_end(summary: str) -> int:
    for index in range(len(summary) - 1, -1, -1):
        mark = summary[index]
        if mark not in _SENTENCE_ENDINGS:
            continue
        if mark == ".":
            previous = summary[index - 1] if index > 0 else ""
            following = summary[index + 1] if index + 1 < len(summary) else ""
            if previous.isdigit() or following.isdigit():
                continue
        return index
    return -1


def _source_summary(manifest: EvidenceManifest) -> str:
    summary = (manifest.source_summary or "").strip()
    summary = re.sub(r"\s+", " ", summary).strip()
    summary = re.split(
        r"\bThe post\b.+\bappeared first on\b", summary, maxsplit=1
    )[0].strip()
    summary = re.sub(r"\[(?:\.\.\.|…|⋯)\]\s*$", "", summary).strip()
    if not summary:
        paragraphs = [
            line.strip()
            for line in manifest.canonical_body.splitlines()
            if line.strip() and not line.startswith("##")
        ]
        summary = paragraphs[0] if paragraphs else ""
    if summary and summary[-1] not in _SENTENCE_ENDINGS:
        complete = _last_sentence_end(summary)
        ending = summary[complete] if complete >= 0 else ""
        if complete >= 30 or (ending in "。！？" and complete >= 8):
            summary = summary[: complete + 1]
    return summary[:800].rstrip()


def _is_topic_relevant(manifest: EvidenceManifest) -> bool:
    if any(evidence.status == "confirmed" for evidence in manifest.evidence):
        return True
    source_text = f"{manifest.article_title}\n{manifest.source_summary or ''}"
    return bool(TOPIC_RE.search(source_text))


def collect_report(
    parser: NewsParser,
    source_keys: list[str],
    *,
    since: datetime,
    until: datetime,
    generated_at: datetime | None = None,
) -> DailyReport:
    manifests: list[EvidenceManifest] = []
    failures: list[SourceFailure] = []
    source_warnings: list[SourceWarning] = []
    retrieved_at = generated_at or datetime.now(timezone.utc)

    checked_keys = list(dict.fromkeys(source_keys))
    for source_key in checked_keys:
        source = SOURCES[source_key]
        try:
            articles = parser.parse_feed(source, since=since, until=until)
        except ParseError as error:
            failures.append(SourceFailure(source_key, source.name, str(error)))
            continue
        manifests.extend(build_manifest(article, retrieved_at) for article in articles)
        source_warnings.extend(
            SourceWarning(source_key, source.name, warning)
            for warning in getattr(parser, "diagnostics", [])
        )

    deduplicated: dict[str, EvidenceManifest] = {}
    for manifest in manifests:
        key = _canonical_article_url(manifest.article_url)
        deduplicated.setdefault(key, manifest)
    all_manifests = sorted(
        deduplicated.values(),
        key=lambda item: (item.published_at or "", item.article_url),
        reverse=True,
    )
    manifests = [item for item in all_manifests if _is_topic_relevant(item)]
    excluded_articles = [
        item for item in all_manifests if not _is_topic_relevant(item)
    ]

    confirmed_iocs = _unique_confirmed(manifests, COUNTED_IOC_TYPES)
    confirmed_filenames = _unique_confirmed(manifests, frozenset({"filename"}))
    identity = {
        "schema": REPORT_SCHEMA_VERSION,
        "window_start": since.astimezone(timezone.utc).isoformat(),
        "window_end": until.astimezone(timezone.utc).isoformat(),
        "generated_at": retrieved_at.astimezone(timezone.utc).isoformat(),
        "sources_checked": checked_keys,
        "articles": [
            (
                manifest.article_url,
                manifest.body_sha256,
                _is_topic_relevant(manifest),
            )
            for manifest in all_manifests
        ],
        "failures": [asdict(failure) for failure in failures],
        "warnings": [asdict(warning) for warning in source_warnings],
    }
    report_id = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    return DailyReport(
        schema_version=REPORT_SCHEMA_VERSION,
        report_id=report_id,
        window_start=since.astimezone(timezone.utc).isoformat(),
        window_end=until.astimezone(timezone.utc).isoformat(),
        generated_at=retrieved_at.astimezone(timezone.utc).isoformat(),
        sources_checked=checked_keys,
        collected_article_count=len(all_manifests),
        article_count=len(manifests),
        excluded_article_count=len(excluded_articles),
        confirmed_ioc_count=len(confirmed_iocs),
        confirmed_filename_count=len(confirmed_filenames),
        count_policy=(
            "IoC total counts globally unique confirmed MD5/SHA1/SHA256, IP, domain, "
            "and URL values. Confirmed filenames are reported separately."
        ),
        articles=manifests,
        excluded_articles=excluded_articles,
        source_failures=failures,
        source_warnings=source_warnings,
    )


def _canonical_article_url(value: str) -> str:
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    netloc = host + (f":{parts.port}" if parts.port else "")
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def _markdown_escape(value: str) -> str:
    escaped = html.escape(value, quote=False)
    return re.sub(r"([\\`*_\[\]{}()#+.!|])", r"\\\1", escaped)


def _markdown_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    return quote(value, safe="/:?&=#%+@,;~-._")


def _unique_article_evidence(
    manifest: EvidenceManifest, status: str
) -> list[Evidence]:
    seen: set[tuple[str, str]] = set()
    results: list[Evidence] = []
    for evidence in manifest.evidence:
        key = (evidence.indicator_type, evidence.normalized_value)
        if evidence.status == status and key not in seen:
            seen.add(key)
            results.append(evidence)
    return results


def render_markdown(report: DailyReport) -> str:
    start = datetime.fromisoformat(report.window_start).astimezone(timezone.utc)
    end = datetime.fromisoformat(report.window_end).astimezone(timezone.utc)
    lines = [
        "# 每日資安新聞 IoC 彙整報告",
        "",
        f"- 查核期間：{start:%Y-%m-%d %H:%M} ～ {end:%Y-%m-%d %H:%M} UTC",
        f"- 查核來源：{len(report.sources_checked)} 個",
        f"- 相關文章：{report.article_count} 篇",
        f"- 明確 IoC：{report.confirmed_ioc_count} 個",
        f"- 可疑檔名：{report.confirmed_filename_count} 個",
        "",
    ]

    for number, manifest in enumerate(report.articles, start=1):
        confirmed = _unique_article_evidence(manifest, "confirmed")
        iocs = [
            evidence
            for evidence in confirmed
            if evidence.indicator_type in COUNTED_IOC_TYPES
        ]
        filenames = [
            evidence
            for evidence in confirmed
            if evidence.indicator_type == "filename"
        ]
        published = (
            datetime.fromisoformat(manifest.published_at).astimezone(timezone.utc)
            if manifest.published_at
            else None
        )
        lines.extend(
            [
                f"## {number}. {_markdown_escape(manifest.article_title)}",
                "",
                f"- 來源：[{_markdown_escape(manifest.source)}]"
                f"({_markdown_url(manifest.article_url)})",
                f"- 發布時間：{published.strftime('%Y-%m-%d %H:%M UTC') if published else '來源未提供'}",
                f"- 重點：{_markdown_escape(_source_summary(manifest))}",
                "",
            ]
        )
        if iocs:
            lines.extend(["### 明確 IoC", ""])
            for evidence in iocs:
                lines.extend(
                    [
                        f"- **{evidence.indicator_type.upper()}**："
                        f"`{_markdown_escape(evidence.normalized_value)}`",
                        f"  - 上下文：{_markdown_escape(evidence.context).replace(chr(10), ' / ')}",
                    ]
                )
        else:
            lines.append("- IoC：原文未提供明確指標。")
        if filenames:
            lines.extend(["", "### 相關檔案", ""])
            for evidence in filenames:
                lines.extend(
                    [
                        f"- `{_markdown_escape(evidence.normalized_value)}`",
                        f"  - 上下文：{_markdown_escape(evidence.context).replace(chr(10), ' / ')}",
                    ]
                )
        lines.append("")

    lines.extend(
        [
            "## 報告說明",
            "",
            "- 僅收錄標題或來源摘要與資安主題明確相關的文章。",
            "- IoC 僅計原文明確列於 IoC 章節的 hash、IP、domain 與 URL；相同值跨文章只計一次。",
            "- 完整證據、候選值、排除理由與程式診斷位於隨附 JSON 稽核檔。",
            "",
        ]
    )
    return "\n".join(lines)


def report_digest(report: DailyReport) -> str:
    return hashlib.sha256(render_markdown(report).encode()).hexdigest()


def serialize_report(report: DailyReport) -> tuple[str, str]:
    markdown = render_markdown(report)
    payload = report.to_dict()
    payload["reader_digest"] = hashlib.sha256(markdown.encode()).hexdigest()
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n", markdown
