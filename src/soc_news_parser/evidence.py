from __future__ import annotations

import hashlib
import ipaddress
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Iterable
from urllib.parse import urlparse

from .parser import ParsedArticle


MANIFEST_VERSION = "1.0"
HASH_RE = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])",
    re.IGNORECASE,
)
URL_RE = re.compile(r"\b(?:hxxps?|https?)://[^\s<>\"']+", re.IGNORECASE)
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}(?:\.|\[\.\]|\(\.\))){3}\d{1,3}(?!\d)")
FILE_RE = re.compile(
    r"(?<![\w.-])[\w@()+-][\w@().+-]*\."
    r"(?:exe|dll|sys|ps1|bat|cmd|vbs|js|jar|py|zip|rar|7z|hta|msi|scr|elf|bin|dat|pem)"
    r"(?![\w.-])",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"(?<![\w@.-])(?:[a-z0-9-]{1,63}(?:\.|\[\.\]|\(\.\))){1,}"
    r"[a-z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
IOC_HEADING_RE = re.compile(
    r"^(?:indicators? of compromise(?: \(iocs?\))?|iocs?|file indicators?|"
    r"network indicators?|hash(?:es)?|domains?|ip addresses?)[:：]?$",
    re.IGNORECASE,
)
EXCLUDED_HEADING_RE = re.compile(
    r"^(?:related articles?|related posts?|latest news|learn more|additional resources|"
    r"references|recommended|more from .+|you may also like)[:：]?$",
    re.IGNORECASE,
)
SECTION_END_RE = re.compile(
    r"^(?:mitigations?|recommendations?|conclusions?|summary|detections?|"
    r"advanced hunting queries|acknowledgements?)[:：]?$",
    re.IGNORECASE,
)
EXPLICIT_MALICIOUS_RE = re.compile(
    r"\b(?:indicator(?:s)? of compromise|ioc|c2|command[- ]and[- ]control|"
    r"malicious (?:file|dll|domain|url|ip|payload)|attacker[- ]controlled|"
    r"payload delivery|custom (?:tunnel )?implant|compromised website|"
    r"initial (?:zip )?archive|dropped (?:file|payload)|backdoor)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    indicator_type: str
    raw_value: str
    normalized_value: str
    line_number: int
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
    retrieved_at: str
    body_sha256: str
    body_characters: int
    extraction_method: str
    parser_version: str
    parser_revision: str | None
    confirmed_unique_iocs: int
    candidate_unique_iocs: int
    rejected_unique_iocs: int
    evidence: list[Evidence]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize(value: str, indicator_type: str) -> str:
    normalized = value.strip().rstrip(".,;:)]}'\"")
    normalized = re.sub(r"\[\.\]|\(\.\)", ".", normalized)
    if indicator_type == "url":
        normalized = re.sub(r"^hxxps://", "https://", normalized, flags=re.I)
        normalized = re.sub(r"^hxxp://", "http://", normalized, flags=re.I)
    return normalized.lower() if indicator_type in {"hash", "domain", "url"} else normalized


def _hash_type(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def _line_matches(line: str) -> Iterable[tuple[str, re.Match[str]]]:
    occupied: list[tuple[int, int]] = []
    patterns = (
        ("hash", HASH_RE),
        ("url", URL_RE),
        ("ip", IP_RE),
        ("filename", FILE_RE),
        ("domain", DOMAIN_RE),
    )
    for indicator_type, pattern in patterns:
        for match in pattern.finditer(line):
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in occupied):
                continue
            if indicator_type == "ip":
                try:
                    ipaddress.ip_address(_normalize(match.group(), "ip"))
                except ValueError:
                    continue
            occupied.append(span)
            yield indicator_type, match


def _source_host_matches(value: str, article_url: str, indicator_type: str) -> bool:
    host = (urlparse(article_url).hostname or "").removeprefix("www.")
    if indicator_type == "url":
        candidate = (urlparse(value).hostname or "").removeprefix("www.")
    elif indicator_type == "domain":
        candidate = value.removeprefix("www.")
    else:
        return False
    return bool(host and candidate == host)


def extract_evidence(article: ParsedArticle) -> list[Evidence]:
    lines = article.body.splitlines()
    current_section = "article body"
    zone = "general"
    results: list[Evidence] = []

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if IOC_HEADING_RE.fullmatch(stripped):
            current_section, zone = stripped, "ioc"
            continue
        if EXCLUDED_HEADING_RE.fullmatch(stripped):
            current_section, zone = stripped, "excluded"
            continue
        if SECTION_END_RE.fullmatch(stripped):
            current_section, zone = stripped, "general"
            continue

        for generic_type, match in _line_matches(line):
            raw = match.group()
            indicator_type = _hash_type(raw) if generic_type == "hash" else generic_type
            normalized = _normalize(raw, generic_type)
            reasons: list[str]
            if zone == "excluded":
                status = "rejected"
                assertion = "machine_rejected"
                reasons = ["excluded_editorial_section"]
            elif _source_host_matches(normalized, article.url, generic_type):
                status = "rejected"
                assertion = "machine_rejected"
                reasons = ["publisher_domain"]
            elif zone == "ioc":
                status = "confirmed"
                assertion = "source_explicit"
                reasons = ["explicit_ioc_section"]
            elif EXPLICIT_MALICIOUS_RE.search(line):
                status = "confirmed"
                assertion = "source_explicit"
                reasons = ["explicit_malicious_relationship"]
            else:
                status = "candidate"
                assertion = "machine_candidate"
                reasons = ["context_requires_human_review"]

            before = lines[index - 2].strip() if index > 1 else ""
            after = lines[index].strip() if index < len(lines) else ""
            context = "\n".join(part for part in (before, stripped, after) if part)
            evidence_id = hashlib.sha256(
                f"{article.url}\n{index}\n{indicator_type}\n{normalized}".encode()
            ).hexdigest()[:20]
            results.append(
                Evidence(
                    evidence_id=evidence_id,
                    indicator_type=indicator_type,
                    raw_value=raw,
                    normalized_value=normalized,
                    line_number=index,
                    section=current_section,
                    context=context,
                    status=status,
                    assertion_kind=assertion,
                    reason_codes=reasons,
                )
            )
    return results


def _package_version() -> str:
    try:
        return version("soc-news-parser")
    except PackageNotFoundError:
        return "unknown"


def _git_revision() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def build_manifest(
    article: ParsedArticle, retrieved_at: datetime | None = None
) -> EvidenceManifest:
    evidence = extract_evidence(article) if article.body else []
    retrieved = retrieved_at or datetime.now(timezone.utc)

    def unique_count(status: str) -> int:
        return len(
            {
                (item.indicator_type, item.normalized_value)
                for item in evidence
                if item.status == status
            }
        )

    limitations = [
        "Only deterministic indicator patterns are extracted; malware-family and ATT&CK "
        "claims require separate source quotations.",
        "Confirmed means the source text explicitly labels the value or relationship; "
        "it does not independently prove that the indicator is malicious or currently active.",
    ]
    if article.extraction_method == "failed":
        limitations.insert(0, "Full article body was unavailable; no IoC decision was made.")

    return EvidenceManifest(
        manifest_version=MANIFEST_VERSION,
        source=article.source,
        article_title=article.title,
        article_url=article.url,
        published_at=article.published_at,
        retrieved_at=retrieved.astimezone(timezone.utc).isoformat(),
        body_sha256=hashlib.sha256(article.body.encode()).hexdigest(),
        body_characters=len(article.body),
        extraction_method=article.extraction_method,
        parser_version=_package_version(),
        parser_revision=_git_revision(),
        confirmed_unique_iocs=unique_count("confirmed"),
        candidate_unique_iocs=unique_count("candidate"),
        rejected_unique_iocs=unique_count("rejected"),
        evidence=evidence,
        limitations=limitations,
    )
