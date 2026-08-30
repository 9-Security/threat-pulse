from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .evidence import (
    COUNTED_IOC_TYPES,
    EXCLUDED_HEADING_RE,
    IOC_HEADING_RE,
    RELATED_LINE_RE,
    SECTION_END_RE,
    Evidence,
    EvidenceManifest,
)


IMPACT_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "remote_code_execution",
        "遠端程式碼執行",
        re.compile(
            r"\b(?:remote code execution|arbitrary code execution|\brce\b|"
            r"遠端程式碼執行)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "authentication_bypass",
        "驗證繞過／帳號接管",
        re.compile(
            r"\b(?:authentication bypass|account takeover|privilege escalation|"
            r"驗證繞過|帳號接管|權限提升)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "data_breach",
        "資料外洩",
        re.compile(
            r"\b(?:data breach|personal information|資料外洩|個資)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ransomware",
        "勒索軟體",
        re.compile(r"\bransomware|勒索軟體\b", re.IGNORECASE),
    ),
    (
        "phishing",
        "釣魚",
        re.compile(r"\bphishing|釣魚\b", re.IGNORECASE),
    ),
    (
        "command_and_control",
        "C2／後控",
        re.compile(r"\b(?:command and control|\bc2\b|指揮控制)\b", re.IGNORECASE),
    ),
)
CVSS_RE = re.compile(r"CVSS(?:\s+score)?\s*[:=]?\s*(\d+(?:\.\d+)?)", re.IGNORECASE)
HIGH_IMPACTS = frozenset(
    {
        "remote_code_execution",
        "authentication_bypass",
        "ransomware",
        "command_and_control",
    }
)
NETWORK_TYPES = frozenset({"ip", "domain", "url"})
HOST_TYPES = frozenset({"md5", "sha1", "sha256", "filename"})
ACTIONABLE = frozenset({"patch", "block", "hunt"})
ACTION_VERBS = {"patch": "修補", "block": "封鎖", "hunt": "hunt"}


@dataclass(frozen=True)
class AnalystAction:
    action: str
    priority: str
    target_type: str
    target: str
    reason: str
    article_title: str
    article_url: str
    is_new: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EventCluster:
    cluster_id: str
    label: str
    cves: list[str]
    article_urls: list[str]
    impacts: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AnalystBrief:
    actions: list[AnalystAction]
    clusters: list[EventCluster]
    patch_count: int
    block_count: int
    hunt_count: int
    monitor_count: int
    new_ioc_count: int | None
    repeat_ioc_count: int | None
    gone_ioc_count: int | None
    priority_line: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": [item.to_dict() for item in self.actions],
            "clusters": [item.to_dict() for item in self.clusters],
            "patch_count": self.patch_count,
            "block_count": self.block_count,
            "hunt_count": self.hunt_count,
            "monitor_count": self.monitor_count,
            "new_ioc_count": self.new_ioc_count,
            "repeat_ioc_count": self.repeat_ioc_count,
            "gone_ioc_count": self.gone_ioc_count,
            "priority_line": self.priority_line,
        }


def _body_for_impacts(body: str) -> str:
    kept: list[str] = []
    zone = "general"
    for line in body.splitlines():
        stripped = line.strip()
        marked = re.fullmatch(r"#{1,6}\s+(.+)", stripped)
        heading = marked.group(1).strip() if marked else stripped
        is_known = any(
            pattern.fullmatch(heading)
            for pattern in (IOC_HEADING_RE, EXCLUDED_HEADING_RE, SECTION_END_RE)
        )
        if marked or is_known:
            zone = "excluded" if EXCLUDED_HEADING_RE.fullmatch(heading) else "general"
            continue
        if zone == "excluded" or RELATED_LINE_RE.match(stripped):
            continue
        kept.append(stripped)
    return "\n".join(kept)


def _article_text(manifest: EvidenceManifest) -> str:
    return "\n".join(
        part
        for part in (
            manifest.article_title,
            manifest.source_summary or "",
            _body_for_impacts(manifest.canonical_body),
        )
        if part
    )


def article_impacts(manifest: EvidenceManifest) -> list[tuple[str, str]]:
    text = _article_text(manifest)
    return [
        (key, label)
        for key, label, pattern in IMPACT_PATTERNS
        if pattern.search(text)
    ]


def article_cvss(manifest: EvidenceManifest) -> float | None:
    scores = [float(match) for match in CVSS_RE.findall(_article_text(manifest))]
    return max(scores) if scores else None


def _confirmed(manifest: EvidenceManifest) -> list[Evidence]:
    seen: set[tuple[str, str]] = set()
    results: list[Evidence] = []
    for evidence in manifest.evidence:
        if evidence.status != "confirmed":
            continue
        key = (evidence.indicator_type, evidence.normalized_value)
        if key in seen:
            continue
        seen.add(key)
        results.append(evidence)
    return results


def _priority(impacts: list[tuple[str, str]], cvss: float | None) -> str:
    keys = {item[0] for item in impacts}
    if cvss is not None and cvss >= 9.0:
        return "high"
    if keys & HIGH_IMPACTS:
        return "high"
    if cvss is not None and cvss >= 7.0:
        return "medium"
    return "medium" if impacts else "low"


def _make_action(
    action: str,
    priority: str,
    target_type: str,
    target: str,
    reason: str,
    manifest: EvidenceManifest,
) -> AnalystAction:
    return AnalystAction(
        action,
        priority,
        target_type,
        target,
        reason,
        manifest.article_title,
        manifest.article_url,
    )


def build_actions(manifest: EvidenceManifest) -> list[AnalystAction]:
    confirmed = _confirmed(manifest)
    impacts = article_impacts(manifest)
    impact_labels = "、".join(label for _, label in impacts) or "原文明確記載"
    cvss = article_cvss(manifest)
    priority = _priority(impacts, cvss)
    actions: list[AnalystAction] = []
    for evidence in confirmed:
        if evidence.indicator_type == "cve":
            score = f"CVSS {cvss:g}" if cvss is not None else "未寫 CVSS"
            actions.append(
                _make_action(
                    "patch",
                    "high" if priority == "high" or (cvss or 0) >= 9 else "medium",
                    "cve",
                    evidence.normalized_value,
                    f"{score}；{impact_labels}",
                    manifest,
                )
            )
        elif evidence.indicator_type in NETWORK_TYPES:
            actions.append(
                _make_action(
                    "block",
                    priority if priority != "low" else "medium",
                    evidence.indicator_type,
                    evidence.normalized_value,
                    f"防火牆／DNS／proxy 封鎖後再 hunt 連線；{impact_labels}",
                    manifest,
                )
            )
        elif evidence.indicator_type in HOST_TYPES:
            actions.append(
                _make_action(
                    "hunt",
                    priority if priority != "low" else "medium",
                    evidence.indicator_type,
                    evidence.normalized_value,
                    f"端點 hash／檔名 hunt；{impact_labels}",
                    manifest,
                )
            )
    if actions:
        return actions
    if any(key == "data_breach" for key, _ in impacts):
        return [
            _make_action(
                "monitor",
                "medium",
                "article",
                manifest.article_title,
                "原文描述外洩但未提供可封鎖指標；追蹤身分與供應商通報",
                manifest,
            )
        ]
    if impacts:
        return [
            _make_action(
                "observe",
                "low",
                "article",
                manifest.article_title,
                f"原文明確提到{impact_labels}，但沒有可立即封鎖或修補的指標",
                manifest,
            )
        ]
    return [
        _make_action(
            "observe",
            "low",
            "article",
            manifest.article_title,
            "主題相關但原文沒有明確處置標的",
            manifest,
        )
    ]


def build_clusters(manifests: list[EvidenceManifest]) -> list[EventCluster]:
    parent = {index: index for index in range(len(manifests))}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    cves_by_article = [
        {
            item.normalized_value
            for item in _confirmed(manifest)
            if item.indicator_type == "cve"
        }
        for manifest in manifests
    ]
    for left, left_cves in enumerate(cves_by_article):
        if not left_cves:
            continue
        for right, right_cves in enumerate(cves_by_article):
            if left < right and left_cves & right_cves:
                parent[find(right)] = find(left)

    groups: dict[int, list[int]] = {}
    for index in range(len(manifests)):
        groups.setdefault(find(index), []).append(index)

    clusters: list[EventCluster] = []
    for members in groups.values():
        cves = sorted({cve for index in members for cve in cves_by_article[index]})
        urls = [manifests[index].article_url for index in members]
        impacts: list[str] = []
        for index in members:
            for _, label in article_impacts(manifests[index]):
                if label not in impacts:
                    impacts.append(label)
        if cves:
            label = f"{cves[0]} 等 {len(cves)} 個 CVE" if len(cves) > 1 else cves[0]
        else:
            label = manifests[members[0]].article_title
        identity = "\n".join(sorted(cves or urls))
        cluster_id = hashlib.sha256(identity.encode()).hexdigest()[:16]
        clusters.append(EventCluster(cluster_id, label, cves, urls, impacts))
    clusters.sort(key=lambda item: (-len(item.cves), -len(item.article_urls), item.label))
    return clusters


def _published_rank(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


def article_sort_key(manifest: EvidenceManifest) -> tuple[int, int, float]:
    confirmed = _confirmed(manifest)
    cves = sum(item.indicator_type == "cve" for item in confirmed)
    iocs = sum(item.indicator_type in COUNTED_IOC_TYPES for item in confirmed)
    return (-cves, -iocs, -_published_rank(manifest.published_at))


def confirmed_ioc_keys(manifests: Iterable[EvidenceManifest]) -> set[tuple[str, str]]:
    return {
        (evidence.indicator_type, evidence.normalized_value)
        for manifest in manifests
        for evidence in _confirmed(manifest)
        if evidence.indicator_type in COUNTED_IOC_TYPES
    }


def load_previous_iocs(path: str) -> set[tuple[str, str]]:
    payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    articles = payload.get("articles") or []
    values: set[tuple[str, str]] = set()
    if not isinstance(articles, list):
        raise ValueError("previous report JSON has no article list")
    for article in articles:
        if not isinstance(article, dict):
            continue
        for evidence in article.get("evidence") or []:
            if not isinstance(evidence, dict):
                continue
            indicator_type = evidence.get("indicator_type")
            value = evidence.get("normalized_value")
            if (
                evidence.get("status") == "confirmed"
                and indicator_type in COUNTED_IOC_TYPES
                and isinstance(value, str)
            ):
                values.add((indicator_type, value))
    return values


def _priority_line(actions: list[AnalystAction]) -> str:
    ranked = [item for item in actions if item.action in ACTIONABLE]
    if not ranked:
        return "今日沒有可立即修補、封鎖或 hunt 的明確指標。"
    high = [item for item in ranked if item.priority == "high"]
    focus = high[0] if high else ranked[0]
    verb = ACTION_VERBS[focus.action]
    counts = {
        "patch": sum(item.action == "patch" for item in ranked),
        "block": sum(item.action == "block" for item in ranked),
        "hunt": sum(item.action == "hunt" for item in ranked),
    }
    extras = []
    if counts["patch"] > 1:
        extras.append(f"{counts['patch']} 個 CVE")
    if counts["block"]:
        extras.append(f"{counts['block']} 個網路指標")
    if counts["hunt"]:
        extras.append(f"{counts['hunt']} 個端點指標")
    suffix = f"（{'、'.join(extras)}）" if extras else ""
    return f"今日優先：{verb} {focus.target}{suffix}"


def build_brief(
    manifests: list[EvidenceManifest],
    previous_iocs: set[tuple[str, str]] | None = None,
) -> AnalystBrief:
    ordered = sorted(manifests, key=article_sort_key)
    actions = [action for manifest in ordered for action in build_actions(manifest)]
    current = confirmed_ioc_keys(ordered)
    if previous_iocs is None:
        marked = actions
        new_count = repeat_count = gone_count = None
    else:
        marked = [
            replace(
                action,
                is_new=(action.target_type, action.target) not in previous_iocs,
            )
            if action.action in ACTIONABLE
            else action
            for action in actions
        ]
        new_count = len(current - previous_iocs)
        repeat_count = len(current & previous_iocs)
        gone_count = len(previous_iocs - current)
    return AnalystBrief(
        actions=marked,
        clusters=build_clusters(ordered),
        patch_count=sum(item.action == "patch" for item in marked),
        block_count=sum(item.action == "block" for item in marked),
        hunt_count=sum(item.action == "hunt" for item in marked),
        monitor_count=sum(item.action in {"monitor", "observe"} for item in marked),
        new_ioc_count=new_count,
        repeat_ioc_count=repeat_count,
        gone_ioc_count=gone_count,
        priority_line=_priority_line(marked),
    )


def render_ioc_csv(
    manifests: list[EvidenceManifest],
    previous_iocs: set[tuple[str, str]] | None = None,
) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "action",
            "priority",
            "is_new",
            "indicator_type",
            "normalized_value",
            "article_title",
            "article_url",
            "reason",
        ]
    )
    for action in build_brief(manifests, previous_iocs=previous_iocs).actions:
        if action.action not in ACTIONABLE:
            continue
        writer.writerow(
            [
                action.action,
                action.priority,
                "" if action.is_new is None else str(action.is_new).lower(),
                action.target_type,
                action.target,
                action.article_title,
                action.article_url,
                action.reason,
            ]
        )
    return output.getvalue()
