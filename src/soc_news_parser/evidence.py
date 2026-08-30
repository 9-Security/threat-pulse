from __future__ import annotations

import hashlib
import ipaddress
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from .parser import ParsedArticle


MANIFEST_VERSION = "1.1"
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
FILE_RE = re.compile(
    r"(?<![\w.-])[\w@+-][\w@().+-]*\."
    r"(?:exe|dll|sys|ps1|bat|cmd|vbs|js|jar|py|zip|rar|7z|hta|msi|scr|"
    r"elf|bin|dat|pem|lnk|iso|img|doc|docx|xls|xlsx|ppt|pptx|pdf)"
    r"(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"(?<![\w@.-])(?:[a-z0-9-]{1,63}(?:\.|\[\.\]|\(\.\))){1,}"
    r"[a-z]{2,63}(?![\w-]|\.[a-z0-9])",
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
FILE_CONTEXT_RE = re.compile(
    r"\b(?:file(?:name)?|attachment|document|payload)\s+"
    r"(?:is|named|called)?\s*[:=]?\s*$",
    re.IGNORECASE,
)


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
    return normalized.lower() if indicator_type in {"hash", "domain"} else normalized


def _hash_type(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def _line_matches(line: str) -> Iterable[tuple[str, re.Match[str]]]:
    occupied: list[tuple[int, int]] = []
    patterns = (
        ("hash", HASH_RE),
        ("url", URL_RE),
        ("ip", IP_RE),
        ("ip", IPV6_RE),
        ("filename", FILE_RE),
        ("domain", DOMAIN_RE),
    )
    for indicator_type, pattern in patterns:
        for match in pattern.finditer(line):
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in occupied):
                continue
            if indicator_type == "domain" and span[0] > 0 and line[span[0] - 1] in "/\\":
                continue
            if indicator_type == "domain":
                labels = _normalize(match.group(), "domain").split(".")
                if any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    for label in labels
                ):
                    continue
            if indicator_type == "ip":
                try:
                    ipaddress.ip_address(_normalize(match.group(), "ip"))
                except ValueError:
                    continue
            occupied.append(span)
            yield indicator_type, match


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


def extract_evidence(article: ParsedArticle) -> list[Evidence]:
    lines = article.body.splitlines()
    body_sha256 = hashlib.sha256(article.body.encode()).hexdigest()
    current_section = "article body"
    zone = "general"
    results: list[Evidence] = []

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        marked_heading = re.fullmatch(r"#{1,6}\s+(.+)", stripped)
        heading = marked_heading.group(1).strip() if marked_heading else stripped
        is_known_heading = any(
            pattern.fullmatch(heading)
            for pattern in (IOC_HEADING_RE, EXCLUDED_HEADING_RE, SECTION_END_RE)
        )
        if marked_heading or is_known_heading:
            current_section, zone = heading, "general"
            if IOC_HEADING_RE.fullmatch(heading):
                zone = "ioc"
            elif EXCLUDED_HEADING_RE.fullmatch(heading):
                zone = "excluded"
            continue

        for generic_type, match in _line_matches(line):
            raw = match.group()
            prefix = line[max(0, match.start() - 80) : match.start()]
            if generic_type == "domain" and FILE_CONTEXT_RE.search(prefix):
                generic_type = "filename"
            indicator_type = _hash_type(raw) if generic_type == "hash" else generic_type
            normalized = _normalize(raw, generic_type)
            reasons: list[str]
            if zone == "excluded":
                status = "rejected"
                assertion = "machine_rejected"
                reasons = ["excluded_editorial_section"]
            elif _source_host_matches(normalized, article, generic_type):
                status = "rejected"
                assertion = "machine_rejected"
                reasons = ["publisher_domain"]
            elif zone == "ioc":
                status = "confirmed"
                assertion = "source_explicit"
                reasons = ["explicit_ioc_section"]
            else:
                status = "candidate"
                assertion = "machine_candidate"
                reasons = ["context_requires_human_review"]

            before = lines[index - 2].strip() if index > 1 else ""
            after = lines[index].strip() if index < len(lines) else ""
            context = "\n".join(part for part in (before, stripped, after) if part)
            evidence_id = hashlib.sha256(
                f"{body_sha256}\n{article.url}\n{index}\n{match.start()}\n"
                f"{match.end()}\n{indicator_type}\n{normalized}".encode()
            ).hexdigest()[:20]
            results.append(
                Evidence(
                    evidence_id=evidence_id,
                    indicator_type=indicator_type,
                    raw_value=raw,
                    normalized_value=normalized,
                    line_number=index,
                    column_start=match.start() + 1,
                    column_end=match.end() + 1,
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

    def unique_count(status: str) -> int:
        return len(
            {
                (item.indicator_type, item.normalized_value)
                for item in evidence
                if item.status == status
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
        source_summary=article.feed_excerpt,
        retrieved_at=retrieved.astimezone(timezone.utc).isoformat(),
        body_sha256=hashlib.sha256(article.body.encode()).hexdigest(),
        canonical_body=article.body,
        body_characters=len(article.body),
        extraction_method=article.extraction_method,
        extraction_warnings=article.warnings,
        parser_version=_package_version(),
        parser_revision=_git_revision(),
        confirmed_unique_iocs=unique_count("confirmed"),
        candidate_unique_iocs=unique_count("candidate"),
        rejected_unique_iocs=unique_count("rejected"),
        unique_counts_by_status_and_type=counts_by_status_and_type,
        evidence=evidence,
        limitations=limitations,
    )
