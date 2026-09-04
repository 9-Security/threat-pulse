from __future__ import annotations

import hashlib
import ipaddress
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib import resources
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from .parser import ParsedArticle, _is_public_address


MANIFEST_VERSION = "1.4"
COUNTED_IOC_TYPES = frozenset({"md5", "sha1", "sha256", "ip", "domain", "url", "cve"})
CLAIM_TYPES = frozenset({"malware_family", "attack_technique"})


def _load_known_tlds() -> frozenset[str]:
    """Delegated TLDs from the bundled IANA root zone list."""
    text = (
        resources.files(__package__)
        .joinpath("data/iana_tlds.txt")
        .read_text(encoding="utf-8")
    )
    return frozenset(
        stripped
        for line in text.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    )


KNOWN_TLDS = _load_known_tlds()


HASH_RE = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])",
    re.IGNORECASE,
)
URL_RE = re.compile(r"\b(?:hxxps?|https?)://[^\s<>\"']+", re.IGNORECASE)
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}(?:\.|\[\.\]|\(\.\))){3}\d{1,3}(?!\d)")
IPV6_RE = re.compile(
    r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])",
    re.IGNORECASE,
)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_VERSION_CONTEXT_RE = re.compile(
    r"(?:versions?\s+up\s+to(?:\s*,\s*and\s+including)?|\band\s+including|\bversions?\b)\s*,?\s*$",
    re.IGNORECASE,
)
FAMILY_RE = re.compile(
    r"""(?ix)
    (?:
        (?:malware(?:\s+family)?|ransomware(?:\s+family)?|backdoor|trojan|
           botnet|wiper|stealer|rat|implant|loader|toolset|
           threat\s+(?:group|actor)|apt(?:\s+group)?)
        \s+(?:family\s+)?(?:known\s+as|named|called|tracked\s+as|dubbed)\s+
        ["']?(?P<named>[A-Z][A-Za-z0-9][\w+.-]{2,40})
    )
    |
    (?:
        ["']?(?P<role_name>[A-Z][A-Za-z0-9][\w+.-]{2,40})["']?
        \s+(?:ransomware|backdoor|stealer|wiper|botnet)\b
    )
    |
    (?:
        (?:惡意程式|勒索軟體|後門|木馬|間諜軟體|攻擊組織)
        \s*(?:家族)?(?:稱為|名為|即)\s*
        ["']?(?P<zh_name>[A-Za-z0-9][\w+.-]{2,40})
    )
    """
)
ATTACK_RE = re.compile(
    r"(?:(?:MITRE\s+)?ATT(?:&|＆)CK|MITRE)\s+(?:technique\s+)?(?:ID\s*)?(T\d{4}(?:\.\d{3})?)"
    r"|"
    r"(T\d{4}(?:\.\d{3})?)\s*(?:(?:MITRE\s+)?ATT(?:&|＆)CK)",
    re.IGNORECASE,
)
GENERIC_CLAIM_NAMES = frozenset(
    {
        "after",
        "against",
        "alleged",
        "another",
        "android",
        "before",
        "claims",
        "confirms",
        "custom",
        "cyber",
        "during",
        "following",
        "generic",
        "group",
        "incident",
        "into",
        "java",
        "known",
        "latest",
        "linux",
        "macos",
        "major",
        "malicious",
        "new",
        "python",
        "recent",
        "related",
        "suspected",
        "that",
        "their",
        "these",
        "this",
        "those",
        "unknown",
        "when",
        "where",
        "which",
        "while",
        "windows",
        "with",
    }
)
RELATED_LINE_RE = re.compile(r"^related(?:\s+articles?)?\s*[:：-]", re.IGNORECASE)
FILE_RE = re.compile(
    r"(?<![\w.-])[\w@+-][\w@().+-]*\."
    r"(?:exe|dll|sys|ps1|bat|cmd|vbs|js|jar|py|zip|rar|7z|hta|msi|scr|"
    r"elf|bin|dat|pem|lnk|iso|img|doc|docx|xls|xlsx|ppt|pptx|pdf|"
    r"tmp|enc|dmp|bak|log|apk|jse|wsf|pif)"
    r"(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"(?<![\w@.-])(?:[a-z0-9-]{1,63}(?:\.|\[\.\]|\(\.\))){1,}"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)
IOC_HEADING_RE = re.compile(
    r"^(?:indicators? of compromise(?: \(iocs?\))?|iocs?|file indicators?|"
    r"network indicators?|hash(?:es)?|domains?|ip addresses?|"
    r"妥協指標|威脅指標|網路指標|檔案指標|指標(?:清單|列表|一覽)?|"
    r"(?:惡意)?(?:雜湊|哈希|檔名|網域|網址)(?:值|清單)?|"
    r"(?:惡意)?IP(?:位址|清單)?)[:：]?$",
    re.IGNORECASE,
)
EXCLUDED_HEADING_RE = re.compile(
    r"^(?:related articles?|related posts?|latest news|learn more|additional resources|"
    r"references|recommended|more from .+|you may also like|"
    r"相關文章|延伸閱讀|參考資料|更多消息)[:：]?$",
    re.IGNORECASE,
)
SECTION_END_RE = re.compile(
    r"^(?:mitigations?|recommendations?|conclusions?|summary|detections?|"
    r"advanced hunting queries|acknowledgements?|"
    r"緩解措施|建議|結論|摘要|偵測)[:：]?$",
    re.IGNORECASE,
)
FILE_CONTEXT_RE = re.compile(
    r"\b(?:file\s*names?|attachments?|documents?|payloads?|files?)\s+"
    r"(?:is|are|named|called)?\s*[:=]?\s*$",
    re.IGNORECASE,
)
def normalize_heading(line: str) -> str:
    text = line.strip()
    text = re.sub(r"^#{1,6}\s+", "", text)
    text = re.sub(r"[*_`]+", "", text)
    text = re.sub(r"\s*\(\s*iocs?\s*\)", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return re.sub(r"[\s:：\-–—*]+$", "", text)


def heading_kind(line: str) -> str | None:
    heading = normalize_heading(line)
    if IOC_HEADING_RE.fullmatch(heading):
        return "ioc"
    if EXCLUDED_HEADING_RE.fullmatch(heading):
        return "excluded"
    if SECTION_END_RE.fullmatch(heading):
        return "end"
    return None


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    indicator_type: str
    raw_value: str
    normalized_value: str
    line_number: int
    column_start: int
    column_end: int
    section: str
    context: str
    status: str
    assertion_kind: str
    reason_codes: list[str]


@dataclass(frozen=True)
class EvidenceManifest:
    manifest_version: str
    source: str
    article_title: str
    article_url: str
    published_at: str | None
    source_summary: str | None
    retrieved_at: str
    body_sha256: str
    canonical_body: str
    body_characters: int
    extraction_method: str
    extraction_warnings: list[str]
    parser_version: str
    parser_revision: str | None
    confirmed_unique_iocs: int
    candidate_unique_iocs: int
    rejected_unique_iocs: int
    unique_counts_by_status_and_type: dict[str, dict[str, int]]
    evidence: list[Evidence]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize(value: str, indicator_type: str) -> str:
    normalized = value.strip().strip("([{<'\"").rstrip(".,;:)]}>'\"")
    normalized = re.sub(r"\[\.\]|\(\.\)", ".", normalized)
    if indicator_type == "url":
        normalized = re.sub(r"^hxxps://", "https://", normalized, flags=re.I)
        normalized = re.sub(r"^hxxp://", "http://", normalized, flags=re.I)
        parts = urlsplit(normalized)
        host = (parts.hostname or "").lower()
        if ":" in host:
            host = f"[{host}]"
        netloc = host
        try:
            if parts.port:
                netloc = f"{netloc}:{parts.port}"
        except ValueError:
            return normalized
        return urlunsplit(
            (parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)
        )
    if indicator_type == "cve":
        return normalized.upper()
    if indicator_type == "attack_technique":
        return normalized.upper()
    return normalized.lower() if indicator_type in {"hash", "domain"} else normalized


def _hash_type(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def _line_matches(line: str) -> Iterable[tuple[str, re.Match[str]]]:
    occupied: list[tuple[int, int]] = []
    patterns = (
        ("cve", CVE_RE),
        ("hash", HASH_RE),
        ("url", URL_RE),
        ("ip", IP_RE),
        ("ip", IPV6_RE),
        ("filename", FILE_RE),
        ("domain", DOMAIN_RE),
    )
    for pattern_type, pattern in patterns:
        for match in pattern.finditer(line):
            indicator_type = pattern_type
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in occupied):
                continue
            if indicator_type == "domain" and span[0] > 0 and line[span[0] - 1] in "/\\":
                continue
            if indicator_type == "domain":
                labels = _normalize(match.group(), "domain").split(".")
                if labels[-1] not in KNOWN_TLDS:
                    # Not a delegated TLD, so this is a dotted artefact rather than
                    # a host. Keep it only when the line names it as a file.
                    if not FILE_CONTEXT_RE.search(line[max(0, span[0] - 80) : span[0]]):
                        continue
                    indicator_type = "filename"
                elif any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    for label in labels
                ):
                    continue
            if indicator_type == "ip":
                prefix = line[: span[0]]
                if IP_VERSION_CONTEXT_RE.search(prefix):
                    continue
                try:
                    ipaddress.ip_address(_normalize(match.group(), "ip"))
                except ValueError:
                    continue
            occupied.append(span)
            yield indicator_type, match


def _claim_matches(line: str) -> Iterable[tuple[str, str, re.Match[str]]]:
    for match in FAMILY_RE.finditer(line):
        name = next(
            value
            for value in (
                match.group("named"),
                match.group("role_name"),
                match.group("zh_name"),
            )
            if value
        )
        if name.lower() in GENERIC_CLAIM_NAMES:
            continue
        yield "malware_family", name, match
    for match in ATTACK_RE.finditer(line):
        technique = next(value for value in match.groups() if value)
        yield "attack_technique", technique, match


def _source_host_matches(
    value: str, article: ParsedArticle, indicator_type: str
) -> bool:
    if indicator_type == "url":
        candidate = (urlsplit(value).hostname or "").removeprefix("www.")
    elif indicator_type == "domain":
        candidate = value.removeprefix("www.")
    else:
        return False
    trusted = article.publisher_hosts or ((urlsplit(article.url).hostname or ""),)
    return any(
        candidate == host.removeprefix("www.")
        or candidate.endswith(f".{host.removeprefix('www.')}")
        for host in trusted
        if host
    )


def _classify(
    *,
    zone: str,
    article: ParsedArticle,
    generic_type: str,
    normalized: str,
) -> tuple[str, str, list[str]]:
    if zone == "excluded":
        return "rejected", "machine_rejected", ["excluded_editorial_section"]
    if _source_host_matches(normalized, article, generic_type):
        return "rejected", "machine_rejected", ["publisher_domain"]
    if generic_type == "ip":
        try:
            if not _is_public_address(normalized):
                return "rejected", "machine_rejected", ["non_public_ip"]
        except ValueError:
            return "rejected", "machine_rejected", ["non_public_ip"]
    if generic_type == "cve":
        return "confirmed", "source_explicit", ["explicit_cve_identifier"]
    if generic_type in {"malware_family", "attack_technique"}:
        return "confirmed", "source_explicit", ["explicit_source_label"]
    if zone == "ioc":
        return "confirmed", "source_explicit", ["explicit_ioc_section"]
    return "candidate", "machine_candidate", ["context_requires_human_review"]


def _evidence_item(
    *,
    article: ParsedArticle,
    body_sha256: str,
    indicator_type: str,
    raw: str,
    normalized: str,
    line_number: int,
    match: re.Match[str],
    section: str,
    context: str,
    status: str,
    assertion: str,
    reasons: list[str],
) -> Evidence:
    evidence_id = hashlib.sha256(
        f"{body_sha256}\n{article.url}\n{line_number}\n{match.start()}\n"
        f"{match.end()}\n{indicator_type}\n{normalized}".encode()
    ).hexdigest()[:20]
    return Evidence(
        evidence_id=evidence_id,
        indicator_type=indicator_type,
        raw_value=raw,
        normalized_value=normalized,
        line_number=line_number,
        column_start=match.start() + 1,
        column_end=match.end() + 1,
        section=section,
        context=context,
        status=status,
        assertion_kind=assertion,
        reason_codes=reasons,
    )


def extract_evidence(article: ParsedArticle) -> list[Evidence]:
    lines = article.body.splitlines()
    body_sha256 = hashlib.sha256(article.body.encode()).hexdigest()
    current_section = "article body"
    zone = "general"
    results: list[Evidence] = []

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        marked_heading = re.fullmatch(r"#{1,6}\s+(.+)", stripped)
        kind = heading_kind(stripped)
        if marked_heading or kind:
            current_section, zone = stripped, "general"
            if kind == "ioc":
                zone = "ioc"
            elif kind == "excluded":
                zone = "excluded"
            continue

        line_zone = "excluded" if RELATED_LINE_RE.match(stripped) else zone
        before = lines[index - 2].strip() if index > 1 else ""
        after = lines[index].strip() if index < len(lines) else ""
        context = "\n".join(part for part in (before, stripped, after) if part)
        found: list[tuple[str, str, re.Match[str]]] = [
            (generic_type, match.group(), match)
            for generic_type, match in _line_matches(line)
        ]
        found.extend(_claim_matches(line))
        for generic_type, raw, match in found:
            prefix = line[max(0, match.start() - 80) : match.start()]
            if generic_type == "domain" and FILE_CONTEXT_RE.search(prefix):
                generic_type = "filename"
            indicator_type = _hash_type(raw) if generic_type == "hash" else generic_type
            normalized = _normalize(raw, generic_type)
            status, assertion, reasons = _classify(
                zone=line_zone,
                article=article,
                generic_type=generic_type,
                normalized=normalized,
            )
            results.append(
                _evidence_item(
                    article=article,
                    body_sha256=body_sha256,
                    indicator_type=indicator_type,
                    raw=raw,
                    normalized=normalized,
                    line_number=index,
                    match=match,
                    section=current_section,
                    context=context,
                    status=status,
                    assertion=assertion,
                    reasons=reasons,
                )
            )
    return results


def _package_version() -> str:
    try:
        return version("soc-news-parser")
    except PackageNotFoundError:
        return "unknown"


def _git_revision() -> str | None:
    package_path = Path(__file__).resolve()
    try:
        root = subprocess.run(
            ["git", "-C", str(package_path.parent), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        revision = subprocess.run(
            ["git", "-C", root, "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", root, "status", "--porcelain", "--untracked-files=no"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        return f"{revision}-dirty" if dirty else revision
    except (OSError, subprocess.SubprocessError):
        return None


def build_manifest(
    article: ParsedArticle, retrieved_at: datetime | None = None
) -> EvidenceManifest:
    evidence = extract_evidence(article) if article.body else []
    retrieved = retrieved_at or datetime.now(timezone.utc)

    def unique_count(status: str, accepted: frozenset[str] | None = None) -> int:
        return len(
            {
                (item.indicator_type, item.normalized_value)
                for item in evidence
                if item.status == status
                and (accepted is None or item.indicator_type in accepted)
            }
        )

    counts_by_status_and_type: dict[str, dict[str, int]] = {}
    for status in ("confirmed", "candidate", "rejected"):
        values = {
            (item.indicator_type, item.normalized_value)
            for item in evidence
            if item.status == status
        }
        type_counts: dict[str, int] = {"total": len(values)}
        for indicator_type, _ in values:
            type_counts[indicator_type] = type_counts.get(indicator_type, 0) + 1
        counts_by_status_and_type[status] = dict(sorted(type_counts.items()))

    limitations = [
        "Only deterministic indicator patterns are extracted; malware-family and ATT&CK "
        "labels are recorded only when the source names them in-sentence.",
        "Confirmed means the source text explicitly labels the value or relationship; "
        "it does not independently prove that the indicator is malicious or currently active.",
        "CVE identifiers are confirmed from explicit CVE IDs; software version strings "
        "that look like IPv4 addresses are not treated as network indicators.",
        "Private, loopback, link-local, multicast, reserved, and unspecified IP "
        "addresses are rejected as non-public and are not counted as IoCs.",
    ]
    if article.extraction_method == "failed":
        limitations.insert(0, "Full article body was unavailable; no IoC decision was made.")

    return EvidenceManifest(
        manifest_version=MANIFEST_VERSION,
        source=article.source,
        article_title=article.title,
        article_url=article.url,
        published_at=article.published_at,
        source_summary=article.feed_excerpt,
        retrieved_at=retrieved.astimezone(timezone.utc).isoformat(),
        body_sha256=hashlib.sha256(article.body.encode()).hexdigest(),
        canonical_body=article.body,
        body_characters=len(article.body),
        extraction_method=article.extraction_method,
        extraction_warnings=article.warnings,
        parser_version=_package_version(),
        parser_revision=_git_revision(),
        confirmed_unique_iocs=unique_count("confirmed", COUNTED_IOC_TYPES),
        candidate_unique_iocs=unique_count("candidate", COUNTED_IOC_TYPES),
        rejected_unique_iocs=unique_count("rejected", COUNTED_IOC_TYPES),
        unique_counts_by_status_and_type=counts_by_status_and_type,
        evidence=evidence,
        limitations=limitations,
    )
