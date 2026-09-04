from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .analyst import (
    AnalystBrief,
    article_impacts,
    article_sort_key,
    body_unavailable,
    build_brief,
    kev_targets,
    unavailable_reason,
)
from .enrich import CveIntel, EnrichmentReport, disabled_report
from .evidence import (
    CLAIM_TYPES,
    COUNTED_IOC_TYPES,
    Evidence,
    EvidenceManifest,
    build_manifest,
)
from .parser import NewsParser, ParseError
from .sources import SOURCES


Enricher = Callable[
    [list[EvidenceManifest]], tuple[Mapping[str, CveIntel], EnrichmentReport]
]

REPORT_SCHEMA_VERSION = "1.5"
CLAIM_LABELS = {
    "malware_family": "惡意程式家族",
    "attack_technique": "攻擊技術",
}
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
    confirmed_claim_count: int
    active_source_count: int
    count_policy: str
    articles: list[EvidenceManifest]
    excluded_articles: list[EvidenceManifest]
    source_failures: list[SourceFailure]
    source_warnings: list[SourceWarning]
    analyst_brief: AnalystBrief
    cve_intel: dict[str, dict[str, Any]] = field(default_factory=dict)
    enrichment: dict[str, Any] = field(default_factory=dict)

    @property
    def kev_count(self) -> int:
        return len(kev_targets(self.analyst_brief.actions))

    @property
    def subject(self) -> str:
        kev = self.kev_count
        patch = f"待修 {self.analyst_brief.patch_count}"
        if kev:
            patch += f"（KEV {kev}）"
        return (
            "[SOC] 每日資安新聞 IoC 彙整報告 - "
            f"{patch} / "
            f"待封鎖 {self.analyst_brief.block_count} / "
            f"待hunt {self.analyst_brief.hunt_count} / "
            f"文章數 {self.article_count}"
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
    previous_iocs: set[tuple[str, str]] | None = None,
    enricher: Enricher | None = None,
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
    manifests = sorted(
        [item for item in all_manifests if _is_topic_relevant(item)],
        key=article_sort_key,
    )
    excluded_articles = [
        item for item in all_manifests if not _is_topic_relevant(item)
    ]
    intel, enrichment_report = (
        enricher(manifests) if enricher else ({}, disabled_report())
    )
    brief = build_brief(manifests, previous_iocs=previous_iocs, intel=intel)

    confirmed_iocs = _unique_confirmed(manifests, COUNTED_IOC_TYPES)
    confirmed_filenames = _unique_confirmed(manifests, frozenset({"filename"}))
    confirmed_claims = _unique_confirmed(manifests, CLAIM_TYPES)
    active_sources = {item.source for item in all_manifests}
    identity = {
        "schema": REPORT_SCHEMA_VERSION,
        "window_start": since.astimezone(timezone.utc).isoformat(),
        "window_end": until.astimezone(timezone.utc).isoformat(),
        "generated_at": retrieved_at.astimezone(timezone.utc).isoformat(),
        "sources_checked": checked_keys,
        "articles": [
            (
                manifest.article_url,
                _findings_digest(manifest),
                _is_topic_relevant(manifest),
            )
            for manifest in all_manifests
        ],
        "failures": [asdict(failure) for failure in failures],
        "warnings": [asdict(warning) for warning in source_warnings],
        # Enrichment shapes the board, so it belongs in the identity - but the
        # lookup timestamp does not, or a rerun of the same window would mint a
        # new report_id and Resend would send the report twice.
        "cve_intel": {
            key: {
                field: item
                for field, item in value.to_dict().items()
                if field != "retrieved_at"
            }
            for key, value in sorted(intel.items())
        },
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
        confirmed_claim_count=len(confirmed_claims),
        active_source_count=len(active_sources),
        count_policy=(
            "IoC total counts globally unique confirmed MD5/SHA1/SHA256, IP, domain, "
            "URL, and CVE values. Confirmed filenames and source-quoted malware-family "
            "or ATT&CK labels are reported separately."
        ),
        articles=manifests,
        excluded_articles=excluded_articles,
        source_failures=failures,
        source_warnings=source_warnings,
        analyst_brief=brief,
        cve_intel={key: value.to_dict() for key, value in sorted(intel.items())},
        enrichment=enrichment_report.to_dict(),
    )


TRACKING_QUERY_KEYS = frozenset({"fbclid", "gclid", "mc_cid", "mc_eid"})


def _canonical_article_url(value: str) -> str:
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host + (f":{port}" if port else "")
    path = parts.path.rstrip("/") or "/"
    query = urlencode(
        [
            (key, item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
            if key.lower() not in TRACKING_QUERY_KEYS
            and not key.lower().startswith("utm_")
        ],
        doseq=True,
    )
    return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))


def _markdown_escape(value: str) -> str:
    escaped = html.escape(value, quote=False)
    return re.sub(r"([\\`*_\[\]{}()#+.!|])", r"\\\1", escaped)


def _markdown_code(value: str) -> str:
    return html.escape(value, quote=False).replace("`", "'")


def _markdown_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    return quote(value, safe="/:?&=#%+@,;~-._")


def _reader_context(evidence: Evidence) -> str:
    parts = [part.strip() for part in evidence.context.splitlines() if part.strip()]
    needle = evidence.normalized_value.lower()
    raw = evidence.raw_value.lower()
    chosen = next(
        (part for part in parts if needle in part.lower() or raw in part.lower()),
        parts[0] if parts else evidence.context,
    )
    chosen = re.sub(r"\s+", " ", chosen).strip()
    if len(chosen) <= 240:
        return chosen
    truncated = chosen[:240].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return f"{truncated}…"


def _context_line(evidence: Evidence) -> str | None:
    """The context line, unless it only repeats the indicator back."""
    context = _reader_context(evidence)
    if not context:
        return None
    flattened = re.sub(r"\s+", " ", context).strip().lower()
    if flattened in {
        evidence.normalized_value.strip().lower(),
        evidence.raw_value.strip().lower(),
    }:
        return None
    return f"  - 上下文：{_markdown_escape(context)}"


ACTION_HEADINGS = {
    "patch": "修補",
    "block": "封鎖",
    "hunt": "Hunt",
    "monitor": "監控",
    "observe": "觀察",
    "review": "人工複核",
}


def _render_analyst_board(report: DailyReport) -> list[str]:
    brief = report.analyst_brief
    if not report.articles:
        return [
            "## 今日處置清單",
            "",
            "期間內沒有主題相關新文；無需立即修補、封鎖或 hunt。",
            "",
        ]
    lines = ["## 今日處置清單", "", f"{_markdown_escape(brief.priority_line)}", ""]
    grouped: dict[str, list] = {}
    for action in brief.actions:
        heading = ACTION_HEADINGS[action.action]
        grouped.setdefault(heading, []).append(action)
    for heading in ("修補", "封鎖", "Hunt", "監控", "觀察", "人工複核"):
        items = grouped.get(heading)
        if not items:
            continue
        lines.extend([f"### {heading}", ""])
        for action in items:
            target = (
                f"`{_markdown_code(action.target)}`"
                if action.target_type != "article"
                else _markdown_escape(action.target)
            )
            marker = " 【KEV】" if action.kev else ""
            marker += " 【新增】" if action.is_new else ""
            lines.append(
                f"- **{action.priority.upper()}** {target}{marker}"
                f" — {_markdown_escape(action.reason)}"
                f" — {_markdown_escape(action.article_title)}"
            )
        lines.append("")
    if brief.clusters:
        lines.extend(["### 事件叢集", ""])
        for cluster in brief.clusters:
            cve_note = f"；CVE：{'、'.join(cluster.cves)}" if cluster.cves else ""
            impact_note = (
                f"；影響：{'、'.join(cluster.impacts)}" if cluster.impacts else ""
            )
            lines.append(
                f"- {_markdown_escape(cluster.label)}"
                f"（{len(cluster.article_urls)} 篇{cve_note}{impact_note}）"
            )
        lines.append("")
    return lines


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


def _kev_was_consulted(report: DailyReport) -> bool:
    """True only when the KEV catalogue was actually loaded for this report.

    Without this the header would print "known-exploited: 0" on a run where
    enrichment was off or the catalogue fetch failed - stating a fact nobody
    checked, which is exactly what this report refuses to do elsewhere.
    """
    data = report.enrichment or {}
    if not data.get("enabled"):
        return False
    # Either field proves the catalogue parsed; a failed fetch leaves both unset.
    return bool(data.get("kev_catalog_version") or data.get("kev_catalog_released"))


def _render_enrichment_note(report: DailyReport) -> list[str]:
    """Say plainly how much of the CVE column is third-party, and how fresh."""
    data = report.enrichment or {}
    if not data.get("enabled"):
        return ["- CVE 加值：未啟用，CVSS 僅取自原文，未比對 CISA KEV"]
    lines: list[str] = []
    released = data.get("kev_catalog_released")
    scored = data.get("cvss_count") or 0
    requested = data.get("requested_cve_count") or 0
    errors = data.get("errors") or []
    if not requested:
        note = ["- CVE 加值：已啟用；今日沒有明確 CVE 需要查詢"]
        if errors:
            note.append(
                f"- CVE 加值有 {len(errors)} 項查詢失敗，KEV／CVSS 欄位今日可能不完整"
                "（明細見 JSON 稽核檔）"
            )
        return note
    detail = f"CISA KEV 與 NVD；{scored}/{requested} 個 CVE 取得 NVD CVSS"
    if released:
        detail += f"；KEV 目錄發布於 {released}"
    lines.append(f"- CVE 加值：{detail}")
    if errors:
        lines.append(
            f"- CVE 加值有 {len(errors)} 項查詢失敗，KEV／CVSS 欄位今日可能不完整"
            "（明細見 JSON 稽核檔）"
        )
    return lines


def _compact_summary(manifest: EvidenceManifest, limit: int = 160) -> str:
    """A gist for the one-line list; the full summary stays in the JSON."""
    summary = _source_summary(manifest)
    if len(summary) <= limit:
        return summary
    head = summary[:limit]
    for ending in _SENTENCE_ENDINGS:
        cut = head.rfind(ending)
        if cut >= limit // 2:
            return head[: cut + 1]
    # Only trim back to a word boundary when one is near the end. CJK text has
    # no spaces, so an early space would otherwise cut the gist down to a stub.
    spaced = head.rsplit(" ", 1)[0].rstrip(" ,;:-")
    if len(spaced) >= limit // 2:
        return f"{spaced}…"
    return f"{head.rstrip(' ,;:-')}…"


def _findings_digest(manifest: EvidenceManifest) -> str:
    """A fingerprint of what the parser found, not of the bytes it read.

    The raw body hash cannot serve as report identity: view counters and
    rotating sidebars change it between two fetches of an unchanged article, so
    a retry of the same slot would mint a new report_id, the Resend idempotency
    key would change with it, and the report would be delivered twice. What the
    report actually says is its findings, and those are stable.
    """
    rows = sorted(
        f"{item.status}\t{item.indicator_type}\t{item.normalized_value}"
        for item in manifest.evidence
    )
    payload = "\n".join([str(body_unavailable(manifest)), *rows])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _split_articles(
    report: DailyReport,
) -> tuple[list[EvidenceManifest], list[EvidenceManifest]]:
    """Full sections for articles with something to show or explain.

    An article that was read and simply held no indicator needs a line, not a
    section; keeping it as one buried the duty board under filler.
    """
    detailed: list[EvidenceManifest] = []
    listed: list[EvidenceManifest] = []
    for manifest in report.articles:
        confirmed = _unique_article_evidence(manifest, "confirmed")
        if confirmed or body_unavailable(manifest):
            detailed.append(manifest)
        else:
            listed.append(manifest)
    return detailed, listed


def render_markdown(report: DailyReport) -> str:
    start = datetime.fromisoformat(report.window_start).astimezone(timezone.utc)
    end = datetime.fromisoformat(report.window_end).astimezone(timezone.utc)
    lines = [
        "# 每日資安新聞 IoC 彙整報告",
        "",
        f"- 查核期間：{start:%Y-%m-%d %H:%M} ～ {end:%Y-%m-%d %H:%M} UTC",
        f"- 查核來源：{len(report.sources_checked)} 個",
        f"- 期間內有新文來源：{report.active_source_count} 個",
        f"- 相關文章：{report.article_count} 篇",
        f"- 明確 IoC：{report.confirmed_ioc_count} 個",
        f"- 可疑檔名：{report.confirmed_filename_count} 個",
        f"- 原文指稱：{report.confirmed_claim_count} 項",
        f"- 待修 CVE：{report.analyst_brief.patch_count} 個",
    ]
    if _kev_was_consulted(report):
        lines.append(f"- 其中已知遭利用（CISA KEV）：{report.kev_count} 個")
    lines.extend(
        [
            f"- 待封鎖：{report.analyst_brief.block_count} 個",
            f"- 待hunt：{report.analyst_brief.hunt_count} 個",
        ]
    )
    if report.analyst_brief.unavailable_count:
        lines.append(
            f"- 未能取得全文：{report.analyst_brief.unavailable_count} 篇（需人工複核）"
        )
    if report.analyst_brief.new_ioc_count is not None:
        lines.extend(
            [
                f"- 較昨日新增 IoC：{report.analyst_brief.new_ioc_count} 個",
                f"- 與昨日重複：{report.analyst_brief.repeat_ioc_count} 個",
                f"- 昨日有、今日未再出現：{report.analyst_brief.gone_ioc_count} 個",
            ]
        )
    lines.extend(_render_enrichment_note(report))
    lines.append("")
    lines.extend(_render_analyst_board(report))

    detailed, listed = _split_articles(report)
    for number, manifest in enumerate(detailed, start=1):
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
        claims = [
            evidence
            for evidence in confirmed
            if evidence.indicator_type in CLAIM_TYPES
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
            ]
        )
        impacts = article_impacts(manifest)
        if impacts:
            lines.append(
                f"- 影響：{_markdown_escape('、'.join(label for _, label in impacts))}"
            )
        article_actions = [
            action
            for action in report.analyst_brief.actions
            if action.article_url == manifest.article_url
            and action.action in {"patch", "block", "hunt", "monitor", "review"}
        ]
        if article_actions:
            first = article_actions[0]
            lines.append(
                f"- 建議：{_markdown_escape(ACTION_HEADINGS[first.action])} — "
                f"{_markdown_escape(first.reason)}"
            )
        lines.append("")
        if iocs:
            lines.extend(["### 明確 IoC", ""])
            for evidence in iocs:
                lines.append(
                    f"- **{evidence.indicator_type.upper()}**："
                    f"`{_markdown_code(evidence.normalized_value)}`"
                )
                if (context := _context_line(evidence)) is not None:
                    lines.append(context)
        elif body_unavailable(manifest):
            lines.append(
                f"- IoC：**未能取得全文**（{_markdown_escape(unavailable_reason(manifest))}）；"
                "本篇是否含指標尚未確認，請人工開啟原文複核。"
            )
        elif filenames or claims:
            kinds = "、".join(
                label
                for present, label in ((filenames, "可疑檔名"), (claims, "原文指稱"))
                if present
            )
            lines.append(
                f"- IoC：無 hash／IP／網域／URL／CVE 類指標；本篇只有{kinds}，見下方。"
            )
        else:
            lines.append("- IoC：原文未提供明確指標。")
        if filenames:
            lines.extend(["", "### 相關檔案", ""])
            for evidence in filenames:
                lines.append(f"- `{_markdown_code(evidence.normalized_value)}`")
                if (context := _context_line(evidence)) is not None:
                    lines.append(context)
        if claims:
            lines.extend(["", "### 原文指稱", ""])
            for evidence in claims:
                label = CLAIM_LABELS[evidence.indicator_type]
                lines.append(
                    f"- **{label}**：`{_markdown_code(evidence.normalized_value)}`"
                )
                if (context := _context_line(evidence)) is not None:
                    lines.append(context)
        lines.append("")

    if listed:
        lines.extend(
            [
                "## 其他相關文章",
                "",
                f"以下 {len(listed)} 篇已擷取全文但未出現明確指標，僅列標題供情勢掌握；"
                "完整正文與候選值見 JSON 稽核檔。",
                "",
            ]
        )
        for manifest in listed:
            published = (
                datetime.fromisoformat(manifest.published_at).astimezone(timezone.utc)
                if manifest.published_at
                else None
            )
            stamp = published.strftime("%m-%d %H:%M") if published else "時間未提供"
            lines.append(
                f"- [{_markdown_escape(manifest.article_title)}]"
                f"({_markdown_url(manifest.article_url)})"
                f" — {_markdown_escape(manifest.source)}"
                f"（{stamp} UTC）— {_markdown_escape(_compact_summary(manifest))}"
            )
        lines.append("")

    lines.extend(
        [
            "## 報告說明",
            "",
            "- 僅收錄標題或來源摘要與資安主題明確相關的文章。",
            "- 處置清單只根據原文明確的 CVE、IoC 章節指標與影響用語，不額外猜測。",
            "- 監控／觀察只在標題或來源摘要寫成外洩、釣魚活動或勒索事件時列出；正文帶過的用語不進清單。",
            "- 公共遞迴 DNS 若出現在 IoC 章節仍會記成 confirmed，但降為 hunt 複核，不列入待封鎖。",
            "- 較昨日新增／重複僅在提供前一日 JSON 時計算，方便值勤交接。",
            "- IoC 計原文明確的 CVE，以及 IoC 章節中的 hash、IP、domain 與 URL；相同值跨文章只計一次。",
            "- 惡意程式家族與 ATT&CK 技術只在原文明確命名時列出，並附原文句子，不計入 IoC 總數。",
            "- 完整證據、候選值、排除理由與程式診斷位於隨附 JSON 稽核檔；CSV 供 SIEM／封鎖清單匯入。",
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
