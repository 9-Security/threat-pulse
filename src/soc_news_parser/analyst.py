from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .enrich import CveIntel
from .evidence import (
    COUNTED_IOC_TYPES,
    CVE_RE,
    RELATED_LINE_RE,
    Evidence,
    EvidenceManifest,
    heading_kind,
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
BREACH_EVENT_RE = re.compile(
    r"\b(?:data breach|breach notification|"
    r"notifying (?:employees|customers|individuals)|"
    r"disclos(?:ed|es|ing) a (?:data )?breach)\b|"
    r"(?:資料外洩|個資外洩|外洩通知)",
    re.IGNORECASE,
)
PHISHING_EVENT_RE = re.compile(
    r"\bphishing\s+(?:campaign|wave|operation|lure|emails?|attacks?)\b|"
    r"釣魚(?:攻擊|活動|郵件|信件|詐騙)",
    re.IGNORECASE,
)
RANSOMWARE_EVENT_RE = re.compile(r"\bransomware\b|勒索軟體", re.IGNORECASE)
PUBLIC_DNS_IPS = frozenset(
    str(ipaddress.ip_address(value))
    for value in (
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "149.112.112.112",
        "208.67.222.222",
        "208.67.220.220",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2620:fe::fe",
        "2620:fe::9",
        "2620:119:35::35",
        "2620:119:53::53",
    )
)
PUBLIC_DNS_HOSTS = frozenset(
    {
        "dns.google",
        "dns.google.com",
        "one.one.one.one",
        "1dot1dot1dot1.cloudflare-dns.com",
        "cloudflare-dns.com",
        "dns.quad9.net",
        "dns.opendns.com",
        "resolver1.opendns.com",
        "resolver2.opendns.com",
    }
)
CSV_HEADER = [
    "action",
    "priority",
    "is_new",
    "indicator_type",
    "normalized_value",
    "article_title",
    "article_url",
    "reason",
    "kev",
    "kev_due_date",
    "cvss_score",
    "cvss_severity",
]
PUBLIC_DNS_REASON = "常見公共 DNS，不建議直接封鎖；改為連線／DNS hunt 複核"
BRAND_REASON = (
    "知名品牌官網或子網域，可能是偽裝頁或 hunting 路徑，不建議直接封鎖"
)
SHORT_PARENT_REASON = (
    "同篇文章已有此短 apex 的子網域；父網域過寬，改為 hunt 複核，不建議直接封鎖"
)
# Official brand apexes only. Match host == apex or host.endswith("." + apex).
# Do not list platform suffixes (gitlab.io, github.io, squarespace.com, it.com).
BRAND_APEXES = frozenset(
    {
        "adobe.com",
        "amazon.com",
        "anthropic.com",
        "apple.com",
        "atlassian.com",
        "brave.com",
        "chatgpt.com",
        "cisco.com",
        "claude.ai",
        "crowdstrike.com",
        "docker.com",
        "facebook.com",
        "github.com",
        "gitlab.com",
        "gmail.com",
        "google.com",
        "ibm.com",
        "icloud.com",
        "intel.com",
        "linkedin.com",
        "live.com",
        "meta.com",
        "microsoft.com",
        "microsoftonline.com",
        "mozilla.org",
        "nvidia.com",
        "office.com",
        "office365.com",
        "openai.com",
        "oracle.com",
        "outlook.com",
        "paloaltonetworks.com",
        "paypal.com",
        "redhat.com",
        "salesforce.com",
        "sentinelone.com",
        "slack.com",
        "twitter.com",
        "ubuntu.com",
        "vmware.com",
        "windows.com",
        "x.com",
        "youtube.com",
        "zoom.us",
    }
)


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
    # Third-party enrichment, never the article's own claim.
    kev: bool | None = None
    kev_due_date: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None

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
        kind = heading_kind(stripped)
        if marked or kind:
            zone = "excluded" if kind == "excluded" else "general"
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


def _impacts_in(text: str) -> list[tuple[str, str]]:
    return [
        (key, label)
        for key, label, pattern in IMPACT_PATTERNS
        if pattern.search(text)
    ]


def article_impacts(manifest: EvidenceManifest) -> list[tuple[str, str]]:
    return _impacts_in(_article_text(manifest))


def _cvss_in(text: str) -> float | None:
    scores = [float(match) for match in CVSS_RE.findall(text)]
    return max(scores) if scores else None


def article_cvss(manifest: EvidenceManifest) -> float | None:
    return _cvss_in(_article_text(manifest))


def _other_cve_present(text: str, current: str) -> bool:
    found = {match.group().upper() for match in CVE_RE.finditer(text)}
    found.discard(current.upper())
    return bool(found)


def _local_window(manifest: EvidenceManifest, evidence: Evidence) -> str:
    needles = {
        evidence.normalized_value.lower(),
        evidence.raw_value.lower(),
    }
    needles.discard("")
    body_lines = _body_for_impacts(manifest.canonical_body).splitlines()
    for index, line in enumerate(body_lines):
        lowered = line.lower()
        if not any(needle in lowered for needle in needles):
            continue
        window = [line]
        if evidence.indicator_type == "cve":
            for following in body_lines[index + 1 :]:
                if not following.strip():
                    break
                if _other_cve_present(following, evidence.normalized_value):
                    break
                window.append(following)
                if len(window) >= 5:
                    break
        elif index + 1 < len(body_lines):
            following = body_lines[index + 1]
            if CVSS_RE.search(following) and not _other_cve_present(
                following, evidence.normalized_value
            ):
                window.append(following)
        return "\n".join(window)
    context_lines = [
        part
        for part in evidence.context.splitlines()
        if any(needle in part.lower() for needle in needles)
    ]
    return "\n".join(context_lines)


def _evidence_impacts_and_cvss(
    manifest: EvidenceManifest, evidence: Evidence
) -> tuple[list[tuple[str, str]], float | None]:
    local = _local_window(manifest, evidence)
    if evidence.indicator_type == "cve":
        return _impacts_in(local), _cvss_in(local)
    scoped = "\n".join(
        part
        for part in (manifest.article_title, manifest.source_summary or "", local)
        if part
    )
    return _impacts_in(scoped), _cvss_in(local)


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


def _headline_text(manifest: EvidenceManifest) -> str:
    return "\n".join(
        part
        for part in (manifest.article_title, manifest.source_summary or "")
        if part
    )


def _headline_events(manifest: EvidenceManifest) -> set[str]:
    text = _headline_text(manifest)
    events: set[str] = set()
    if BREACH_EVENT_RE.search(text):
        events.add("data_breach")
    if PHISHING_EVENT_RE.search(text):
        events.add("phishing")
    if RANSOMWARE_EVENT_RE.search(text):
        events.add("ransomware")
    return events


def _network_host(target_type: str, target: str) -> str:
    if target_type == "ip":
        return ""
    host = target
    if target_type == "url":
        host = urlsplit(target).hostname or ""
    return host.lower().strip(".")


def is_public_dns(target_type: str, target: str) -> bool:
    if target_type == "ip":
        try:
            return str(ipaddress.ip_address(target)) in PUBLIC_DNS_IPS
        except ValueError:
            return False
    host = _network_host(target_type, target).removeprefix("www.")
    return any(host == item or host.endswith(f".{item}") for item in PUBLIC_DNS_HOSTS)


def is_official_brand_host(target_type: str, target: str) -> bool:
    host = _network_host(target_type, target)
    if not host:
        return False
    return any(host == apex or host.endswith(f".{apex}") for apex in BRAND_APEXES)


def is_short_parent_of_confirmed_host(host: str, article_hosts: set[str]) -> bool:
    labels = host.split(".")
    if len(labels) != 2 or len(labels[0]) > 3:
        return False
    return any(
        other != host and other.endswith(f".{host}") for other in article_hosts
    )


def _make_action(
    action: str,
    priority: str,
    target_type: str,
    target: str,
    reason: str,
    manifest: EvidenceManifest,
    intel: CveIntel | None = None,
) -> AnalystAction:
    return AnalystAction(
        action,
        priority,
        target_type,
        target,
        reason,
        manifest.article_title,
        manifest.article_url,
        kev=intel.kev if intel else None,
        kev_due_date=intel.kev_due_date if intel else None,
        cvss_score=intel.cvss_score if intel else None,
        cvss_severity=intel.cvss_severity if intel else None,
    )


def _cve_priority(
    impacts: list[tuple[str, str]],
    article_cvss: float | None,
    intel: CveIntel | None,
) -> str:
    """KEV outranks every text signal: it is confirmed in-the-wild exploitation."""
    if intel and intel.kev:
        return "high"
    score = intel.cvss_score if intel and intel.cvss_score is not None else article_cvss
    if score is not None and score >= 9.0:
        return "high"
    if _priority(impacts, score) == "high":
        return "high"
    return "medium"


def _cve_reason(
    local_labels: str, article_cvss: float | None, intel: CveIntel | None
) -> str:
    parts: list[str] = []
    if intel and intel.kev:
        kev_note = "KEV 已知遭利用"
        if intel.kev_due_date:
            kev_note += f"，CISA 修補期限 {intel.kev_due_date}"
        if intel.kev_known_ransomware:
            kev_note += "，已用於勒索攻擊"
        parts.append(kev_note)
    if intel and intel.cvss_score is not None:
        label = f"CVSS {intel.cvss_score:g}"
        if intel.cvss_severity:
            label += f" {intel.cvss_severity}"
        parts.append(f"{label}（NVD）")
    elif article_cvss is not None:
        parts.append(f"CVSS {article_cvss:g}（原文）")
    elif intel and intel.nvd_status and intel.nvd_status != "Unknown":
        parts.append(f"NVD {intel.nvd_status}")
    else:
        parts.append("未寫 CVSS")
    parts.append(local_labels)
    return "；".join(parts)


def build_actions(
    manifest: EvidenceManifest,
    intel: Mapping[str, CveIntel] | None = None,
) -> list[AnalystAction]:
    confirmed = _confirmed(manifest)
    article_hosts = {
        host
        for evidence in confirmed
        if (host := _network_host(evidence.indicator_type, evidence.normalized_value))
    }
    actions: list[AnalystAction] = []
    for evidence in confirmed:
        local_impacts, cvss = _evidence_impacts_and_cvss(manifest, evidence)
        local_labels = "、".join(label for _, label in local_impacts) or "原文明確記載"
        priority = _priority(local_impacts, cvss)
        if evidence.indicator_type == "cve":
            cve_intel = (intel or {}).get(evidence.normalized_value.upper())
            actions.append(
                _make_action(
                    "patch",
                    _cve_priority(local_impacts, cvss, cve_intel),
                    "cve",
                    evidence.normalized_value,
                    _cve_reason(local_labels, cvss, cve_intel),
                    manifest,
                    cve_intel,
                )
            )
        elif evidence.indicator_type in NETWORK_TYPES:
            host = _network_host(evidence.indicator_type, evidence.normalized_value)
            if is_public_dns(evidence.indicator_type, evidence.normalized_value):
                actions.append(
                    _make_action(
                        "hunt",
                        "low",
                        evidence.indicator_type,
                        evidence.normalized_value,
                        PUBLIC_DNS_REASON,
                        manifest,
                    )
                )
            elif is_official_brand_host(
                evidence.indicator_type, evidence.normalized_value
            ):
                actions.append(
                    _make_action(
                        "hunt",
                        "low",
                        evidence.indicator_type,
                        evidence.normalized_value,
                        BRAND_REASON,
                        manifest,
                    )
                )
            elif host and is_short_parent_of_confirmed_host(host, article_hosts):
                actions.append(
                    _make_action(
                        "hunt",
                        "low",
                        evidence.indicator_type,
                        evidence.normalized_value,
                        SHORT_PARENT_REASON,
                        manifest,
                    )
                )
            else:
                actions.append(
                    _make_action(
                        "block",
                        priority if priority != "low" else "medium",
                        evidence.indicator_type,
                        evidence.normalized_value,
                        f"防火牆／DNS／proxy 封鎖後再 hunt 連線；{local_labels}",
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
                    f"端點 hash／檔名 hunt；{local_labels}",
                    manifest,
                )
            )
    if actions:
        return actions
    events = _headline_events(manifest)
    if "data_breach" in events:
        return [
            _make_action(
                "monitor",
                "medium",
                "article",
                manifest.article_title,
                "標題或來源摘要描述外洩事件，但未提供可封鎖指標；追蹤身分與供應商通報",
                manifest,
            )
        ]
    if "phishing" in events or "ransomware" in events:
        label = "釣魚活動" if "phishing" in events else "勒索事件"
        return [
            _make_action(
                "observe",
                "low",
                "article",
                manifest.article_title,
                f"標題或來源摘要寫成{label}，但沒有可立即封鎖或修補的指標",
                manifest,
            )
        ]
    return []


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
        urls = [manifests[index].article_url for index in members]
        if len(urls) < 2:
            continue
        cves = sorted({cve for index in members for cve in cves_by_article[index]})
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


def _unique_action_targets(
    actions: list[AnalystAction], action_name: str
) -> set[tuple[str, str]]:
    return {
        (item.target_type, item.target)
        for item in actions
        if item.action == action_name
    }


def kev_targets(actions: Iterable[AnalystAction]) -> set[str]:
    return {item.target for item in actions if item.action == "patch" and item.kev}


def _priority_line(actions: list[AnalystAction]) -> str:
    ranked = [item for item in actions if item.action in ACTIONABLE]
    if not ranked:
        return "今日沒有可立即修補、封鎖或 hunt 的明確指標。"
    kev = [item for item in ranked if item.action == "patch" and item.kev]
    high = [item for item in ranked if item.priority == "high"]
    focus = kev[0] if kev else (high[0] if high else ranked[0])
    verb = ACTION_VERBS[focus.action]
    counts = {
        "patch": len(_unique_action_targets(ranked, "patch")),
        "block": len(_unique_action_targets(ranked, "block")),
        "hunt": len(_unique_action_targets(ranked, "hunt")),
    }
    extras = []
    kev_count = len(kev_targets(ranked))
    if kev_count:
        extras.append(f"{kev_count} 個已知遭利用")
    if counts["patch"] > 1:
        extras.append(f"{counts['patch']} 個 CVE")
    if counts["block"]:
        extras.append(f"{counts['block']} 個網路指標")
    if counts["hunt"]:
        extras.append(f"{counts['hunt']} 個 hunt 指標")
    suffix = f"（{'、'.join(extras)}）" if extras else ""
    lead = "今日優先：KEV " if kev else "今日優先："
    return f"{lead}{verb} {focus.target}{suffix}"


def _kev_first(actions: list[AnalystAction]) -> list[AnalystAction]:
    """Keep every list in source order except patch, where KEV leads."""
    patch = [item for item in actions if item.action == "patch"]
    if not any(item.kev for item in patch):
        return actions
    ranked = sorted(
        patch,
        key=lambda item: (
            not item.kev,
            # Severity leads inside KEV: a long-overdue low-scoring entry is
            # background, not the thing to open the duty report with.
            -(item.cvss_score or 0.0),
            item.kev_due_date or "9999-99-99",
            item.target,
        ),
    )
    stream = iter(ranked)
    return [next(stream) if item.action == "patch" else item for item in actions]


def build_brief(
    manifests: list[EvidenceManifest],
    previous_iocs: set[tuple[str, str]] | None = None,
    intel: Mapping[str, CveIntel] | None = None,
) -> AnalystBrief:
    ordered = sorted(manifests, key=article_sort_key)
    actions = [
        action for manifest in ordered for action in build_actions(manifest, intel)
    ]
    actions = _kev_first(actions)
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
        patch_count=len(_unique_action_targets(marked, "patch")),
        block_count=len(_unique_action_targets(marked, "block")),
        hunt_count=len(_unique_action_targets(marked, "hunt")),
        monitor_count=len(
            {
                item.article_url
                for item in marked
                if item.action in {"monitor", "observe"}
            }
        ),
        new_ioc_count=new_count,
        repeat_ioc_count=repeat_count,
        gone_ioc_count=gone_count,
        priority_line=_priority_line(marked),
    )


def _csv_is_new(value: bool | None) -> str:
    return "" if value is None else str(value).lower()


def _csv_flag(value: bool | None) -> str:
    return "" if value is None else str(value).lower()


def _csv_score(value: Any) -> str:
    return f"{value:g}" if isinstance(value, (int, float)) else ""


def render_ioc_csv_from_actions(actions: Iterable[AnalystAction | dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_HEADER)
    for action in actions:
        if isinstance(action, AnalystAction):
            if action.action not in ACTIONABLE:
                continue
            writer.writerow(
                [
                    action.action,
                    action.priority,
                    _csv_is_new(action.is_new),
                    action.target_type,
                    action.target,
                    action.article_title,
                    action.article_url,
                    action.reason,
                    _csv_flag(action.kev),
                    action.kev_due_date or "",
                    _csv_score(action.cvss_score),
                    action.cvss_severity or "",
                ]
            )
            continue
        name = action.get("action")
        if name not in ACTIONABLE:
            continue
        writer.writerow(
            [
                name,
                action.get("priority", ""),
                _csv_is_new(action.get("is_new") if isinstance(action.get("is_new"), bool) else None),
                action.get("target_type", ""),
                action.get("target", ""),
                action.get("article_title", ""),
                action.get("article_url", ""),
                action.get("reason", ""),
                _csv_flag(action.get("kev") if isinstance(action.get("kev"), bool) else None),
                action.get("kev_due_date") or "",
                _csv_score(action.get("cvss_score")),
                action.get("cvss_severity") or "",
            ]
        )
    return output.getvalue()


def render_ioc_csv_from_report_dict(payload: dict[str, Any]) -> str:
    brief = payload.get("analyst_brief") or {}
    actions = brief.get("actions") if isinstance(brief, dict) else None
    if not isinstance(actions, list):
        return render_ioc_csv_from_actions([])
    return render_ioc_csv_from_actions(
        item for item in actions if isinstance(item, dict)
    )


def render_ioc_csv(
    manifests: list[EvidenceManifest],
    previous_iocs: set[tuple[str, str]] | None = None,
    intel: Mapping[str, CveIntel] | None = None,
) -> str:
    return render_ioc_csv_from_actions(
        build_brief(manifests, previous_iocs=previous_iocs, intel=intel).actions
    )
