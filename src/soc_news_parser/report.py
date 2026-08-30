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
    article_count: int
    confirmed_ioc_count: int
    confirmed_filename_count: int
    count_policy: str
    articles: list[EvidenceManifest]
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

    for source_key in dict.fromkeys(source_keys):
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
    manifests = sorted(
        deduplicated.values(),
        key=lambda item: (item.published_at or "", item.article_url),
        reverse=True,
    )

    confirmed_iocs = _unique_confirmed(manifests, COUNTED_IOC_TYPES)
    confirmed_filenames = _unique_confirmed(manifests, frozenset({"filename"}))
    identity = {
        "schema": REPORT_SCHEMA_VERSION,
        "window_start": since.astimezone(timezone.utc).isoformat(),
        "window_end": until.astimezone(timezone.utc).isoformat(),
        "generated_at": retrieved_at.astimezone(timezone.utc).isoformat(),
        "articles": [
            (manifest.article_url, manifest.body_sha256) for manifest in manifests
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
        article_count=len(manifests),
        confirmed_ioc_count=len(confirmed_iocs),
        confirmed_filename_count=len(confirmed_filenames),
        count_policy=(
            "IoC total counts globally unique confirmed MD5/SHA1/SHA256, IP, domain, "
            "and URL values. Confirmed filenames are reported separately."
        ),
        articles=manifests,
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
    escaped = html.escape(value, quote=True)
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
    lines = [
        "# 每日資安新聞 IoC 彙整報告",
        "",
        f"- Report ID：`{report.report_id}`",
        f"- 郵件主旨：`{report.subject}`",
        f"- 查核區間：{report.window_start} ～ {report.window_end}",
        f"- 產生時間：{report.generated_at}",
        f"- 文章數：{report.article_count}",
        f"- Confirmed IoC 數：{report.confirmed_ioc_count}",
        f"- Confirmed 可疑檔名數：{report.confirmed_filename_count}",
        f"- 計數政策：{report.count_policy}",
        "",
        "> `confirmed` 代表來源文字明確標示，不代表本系統獨立證實其惡意性或目前仍有效。",
        "",
    ]

    if report.source_failures:
        lines.extend(["## 來源擷取失敗", ""])
        for failure in report.source_failures:
            lines.append(
                f"- **{_markdown_escape(failure.source_name)}** "
                f"(`{_markdown_escape(failure.source_key)}`)："
                f"{_markdown_escape(failure.error)}"
            )
        lines.append("")

    if report.source_warnings:
        lines.extend(["## 來源資料警告", ""])
        for warning in report.source_warnings:
            lines.append(
                f"- **{_markdown_escape(warning.source_name)}** "
                f"(`{_markdown_escape(warning.source_key)}`)："
                f"{_markdown_escape(warning.warning)}"
            )
        lines.append("")

    for number, manifest in enumerate(report.articles, start=1):
        confirmed = _unique_article_evidence(manifest, "confirmed")
        candidate = _unique_article_evidence(manifest, "candidate")
        rejected = _unique_article_evidence(manifest, "rejected")
        lines.extend(
            [
                f"## {number}\\. {_markdown_escape(manifest.source)}",
                "",
                f"### [{_markdown_escape(manifest.article_title)}]"
                f"({_markdown_url(manifest.article_url)})",
                "",
                f"- 發布時間：{manifest.published_at or '來源未提供'}",
                f"- 正文擷取：`{manifest.extraction_method}`；"
                f"{manifest.body_characters} 字元",
                f"- 正文 SHA-256：`{manifest.body_sha256}`",
                f"- Parser：`{manifest.parser_version}`"
                + (
                    f" (`{manifest.parser_revision}`)"
                    if manifest.parser_revision
                    else ""
                ),
                f"- 證據狀態：confirmed {len(confirmed)} / "
                f"candidate {len(candidate)} / rejected {len(rejected)}",
                f"- 擷取警告：{len(manifest.extraction_warnings)}",
                "",
            ]
        )
        if manifest.extraction_method == "failed":
            lines.extend(["**正文擷取失敗，未執行 IoC 判定。**", ""])
            continue
        if not confirmed:
            lines.extend(["**無擷取到 confirmed IoC。**", ""])
        else:
            lines.extend(["#### Confirmed indicators", ""])
            for evidence in confirmed:
                lines.extend(
                    [
                        f"- **{evidence.indicator_type}**："
                        f"`{_markdown_escape(evidence.normalized_value)}`",
                        f"  - 原值：`{_markdown_escape(evidence.raw_value)}`",
                        f"  - 證據：L{evidence.line_number}，"
                        f"章節「{_markdown_escape(evidence.section)}」，"
                        f"理由 `{','.join(evidence.reason_codes)}`",
                        f"  - 上下文：{_markdown_escape(evidence.context).replace(chr(10), ' / ')}",
                    ]
                )
            lines.append("")
        if candidate or rejected:
            lines.extend(
                [
                    "#### 待複核與排除摘要",
                    "",
                    f"- Candidate 唯一值：{len(candidate)}（不納入主旨統計）",
                    f"- Rejected 唯一值：{len(rejected)}（不納入主旨統計）",
                    "- 完整逐筆理由請查閱同批 JSON evidence manifest。",
                    "",
                ]
            )

    lines.extend(
        [
            "## 可驗證性與限制",
            "",
            "- JSON 稽核檔保留 confirmed、candidate、rejected 的所有 occurrence。",
            f"- JSON 與 Markdown 應具有相同 Report ID：`{report.report_id}`。",
            "- 相同 indicator 在多篇文章出現時，主旨只計一次。",
            "- 惡意工具家族、攻擊手法摘要及 ATT&CK 對映不由 regex 推測；"
            "必須附來源引句後另行加入。",
            "- 原文內容變更時，正文 SHA-256 會改變，應重新複核。",
            "",
        ]
    )
    return "\n".join(lines)


def report_digest(report: DailyReport) -> str:
    return hashlib.sha256(render_markdown(report).encode()).hexdigest()
