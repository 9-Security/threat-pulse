from __future__ import annotations

import html
import ipaddress
import json
import re
import socket
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlparse

import feedparser
import httpx
import trafilatura
from bs4 import BeautifulSoup, Tag

from .sources import SOURCES, Source


def _package_version() -> str:
    try:
        return version("soc-news-parser")
    except PackageNotFoundError:
        return "0.13.1"


USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0 Safari/537.36 "
    f"SOC-News-Parser/{_package_version()}"
)
MAX_JSON_LD_NODES = 64
BLOCK_PAGE_MARKERS = (
    "performing security verification",
    "enable javascript and cookies to continue",
    "checking your browser before accessing",
    "access denied",
)
UNWANTED_SELECTORS = (
    "script",
    "style",
    "noscript",
    "nav",
    "footer",
    "aside",
    "form",
    ".advertisement",
    ".ad",
    ".related",
    ".recommended",
    ".newsletter",
    ".social-share",
    ".author-bio",
    ".comments",
)


class ParseError(RuntimeError):
    pass


@dataclass
class ParsedArticle:
    source: str
    title: str
    url: str
    published_at: str | None
    body: str
    extraction_method: str
    body_characters: int
    warnings: list[str]
    feed_excerpt: str | None = None
    publisher_hosts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _clean_text(value: str) -> str:
    value = BeautifulSoup(html.unescape(value), "lxml").get_text("\n")
    value = value.replace("\xa0", " ")
    lines = (re.sub(r"[ \t]+", " ", line).strip() for line in value.splitlines())
    return "\n".join(line for line in lines if line)


def _looks_like_body(
    text: str, expected_title: str = "", min_characters: int = 500
) -> tuple[bool, list[str]]:
    warnings: list[str] = []
    lowered = text.lower()
    opening = lowered[:1500]
    marker_count = sum(marker in opening for marker in BLOCK_PAGE_MARKERS)
    if marker_count >= 2 or opening.lstrip().startswith("access denied"):
        return False, ["anti-bot or access-denied page detected"]
    if len(text) < min_characters:
        return False, [f"body too short ({len(text)} characters)"]
    if text.count("\n") < 3:
        warnings.append("body has unusually few text blocks")
    if expected_title:
        title_terms = {
            token
            for token in re.findall(r"[a-z0-9]{4,}", expected_title.lower())
            if token not in {"with", "from", "that", "this", "your"}
        }
        sample = lowered[:4000]
        if title_terms and not title_terms.intersection(sample):
            warnings.append("article title terms are absent from extracted body")
    return True, warnings


def _tag_text(tag: Tag) -> str:
    clone = BeautifulSoup(str(tag), "lxml")
    for selector in UNWANTED_SELECTORS:
        for node in clone.select(selector):
            node.decompose()
    blocks: list[str] = []
    for node in clone.select("h1, h2, h3, h4, h5, h6, p, li, pre, blockquote, tr"):
        text = " ".join(node.stripped_strings)
        if node.name and re.fullmatch(r"h[1-6]", node.name):
            text = f"## {text}"
        if text and (not blocks or blocks[-1] != text):
            blocks.append(text)
    return "\n".join(blocks) if blocks else _clean_text(clone.get_text("\n"))


def _clean_body_text(value: str) -> str:
    if re.search(r"<(?:article|main|h[1-6]|p|div|table|li)\b", value, re.I):
        return _tag_text(BeautifulSoup(html.unescape(value), "lxml"))
    return _clean_text(value)


def _resolve_host(host: str) -> list[str]:
    try:
        return sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            }
        )
    except socket.gaierror as error:
        raise ParseError(f"DNS resolution failed for {host}: {error}") from error


def _is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _host_allowed(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    normalized = host.rstrip(".").lower()
    return any(
        normalized == allowed.rstrip(".").lower()
        or normalized.endswith(f".{allowed.rstrip('.').lower()}")
        for allowed in allowed_hosts
    )


def _json_ld_candidates(soup: BeautifulSoup) -> Iterable[str]:
    for script in soup.select("script[type='application/ld+json']"):
        raw = script.string or script.get_text()
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        queue = payload if isinstance(payload, list) else [payload]
        seen: set[int] = set()
        index = 0
        visited = 0
        while index < len(queue) and visited < MAX_JSON_LD_NODES:
            item = queue[index]
            index += 1
            marker = id(item)
            if marker in seen:
                continue
            seen.add(marker)
            if not isinstance(item, dict):
                continue
            visited += 1
            graph = item.get("@graph")
            if isinstance(graph, list):
                room = MAX_JSON_LD_NODES - len(queue)
                if room > 0:
                    queue.extend(graph[:room])
            if isinstance(item.get("articleBody"), str):
                yield _clean_text(item["articleBody"])


class NewsParser:
    def __init__(
        self,
        timeout: float = 25.0,
        resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self.client = httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/rss+xml,"
                "application/atom+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8,zh-TW;q=0.7",
            },
        )
        self.resolver = resolver or _resolve_host
        self.diagnostics: list[str] = []

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> NewsParser:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _validate_url(self, url: str, allowed_hosts: tuple[str, ...]) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ParseError(f"only HTTPS URLs with a hostname are allowed: {url}")
        host = parsed.hostname.rstrip(".").lower()
        if not _host_allowed(host, allowed_hosts):
            raise ParseError(f"host {host} is not allowed for this source")
        try:
            addresses = [host] if ipaddress.ip_address(host) else []
        except ValueError:
            addresses = self.resolver(host)
        if not addresses or any(not _is_public_address(address) for address in addresses):
            raise ParseError(f"host {host} resolves to a non-public address")

    def _get(
        self, url: str, *, allowed_hosts: tuple[str, ...] | None = None
    ) -> httpx.Response:
        initial_host = urlparse(url).hostname
        hosts = allowed_hosts or ((initial_host,) if initial_host else ())
        current_url = url
        maximum_bytes = 12 * 1024 * 1024
        for _ in range(6):
            self._validate_url(current_url, hosts)
            try:
                with self.client.stream("GET", current_url) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise ParseError(
                                f"redirect without Location header: {current_url}"
                            )
                        current_url = urljoin(current_url, location)
                        continue
                    response.raise_for_status()
                    length = response.headers.get("content-length")
                    if length and int(length) > maximum_bytes:
                        raise ParseError(f"response exceeds 12 MiB: {current_url}")
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > maximum_bytes:
                            raise ParseError(f"response exceeds 12 MiB: {current_url}")
                        chunks.append(chunk)
                    decoded_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() not in {"content-encoding", "content-length"}
                    }
                    return httpx.Response(
                        response.status_code,
                        headers=decoded_headers,
                        content=b"".join(chunks),
                        request=response.request,
                    )
            except (httpx.HTTPError, ValueError) as error:
                raise ParseError(
                    f"HTTP fetch failed for {current_url}: {error}"
                ) from error
        raise ParseError(f"too many redirects while fetching {url}")

    def extract_html(
        self,
        url: str,
        *,
        expected_title: str = "",
        selectors: tuple[str, ...] = (),
        allowed_hosts: tuple[str, ...] = (),
        min_body_characters: int = 500,
    ) -> tuple[str, str, list[str]]:
        response = self._get(url, allowed_hosts=allowed_hosts or None)
        page = response.text
        soup = BeautifulSoup(page, "lxml")
        attempts: list[tuple[str, str]] = []

        for selector in selectors:
            node = soup.select_one(selector)
            if node:
                attempts.append((f"site-selector:{selector}", _tag_text(node)))

        attempts.extend(("json-ld:articleBody", body) for body in _json_ld_candidates(soup))

        extracted = trafilatura.extract(
            page,
            url=str(response.url),
            include_comments=False,
            include_tables=True,
            include_links=False,
            favor_precision=True,
            output_format="markdown",
        )
        if extracted:
            attempts.append(("trafilatura", extracted))

        for selector in ("article", "main", "[role='main']"):
            node = soup.select_one(selector)
            if node:
                attempts.append((f"semantic-selector:{selector}", _tag_text(node)))

        failures: list[str] = []
        valid_attempts: list[tuple[float, str, str, list[str]]] = []
        for method, candidate in attempts:
            body = _clean_body_text(candidate)
            valid, warnings = _looks_like_body(
                body, expected_title, min_body_characters
            )
            if valid:
                title_terms = set(re.findall(r"[a-z0-9]{4,}", expected_title.lower()))
                title_hits = sum(term in body[:4000].lower() for term in title_terms)
                title_score = title_hits / max(1, len(title_terms))
                method_score = (
                    30
                    if method.startswith("json-ld")
                    else 25
                    if method.startswith("site-selector")
                    else 20
                    if method == "trafilatura"
                    else 10
                )
                score = method_score + title_score * 40 + min(len(body), 20_000) / 1000
                valid_attempts.append((score, method, body, warnings))
                continue
            failures.append(f"{method}: {', '.join(warnings)}")
        if valid_attempts:
            _, method, body, warnings = max(valid_attempts, key=lambda item: item[0])
            return body, method, warnings
        detail = "; ".join(failures) if failures else "no extraction candidates"
        raise ParseError(f"could not extract a valid article body from {url}: {detail}")

    def parse_feed(
        self,
        source: Source,
        *,
        since: datetime,
        until: datetime,
        limit: int | None = None,
    ) -> list[ParsedArticle]:
        self.diagnostics = []
        feed_host = urlparse(source.feed_url).hostname or ""
        response = self._get(
            source.feed_url,
            allowed_hosts=tuple(dict.fromkeys((feed_host, *source.article_hosts))),
        )
        parsed = feedparser.parse(response.content)
        if parsed.bozo:
            if not parsed.entries:
                raise ParseError(
                    f"invalid feed {source.feed_url}: {parsed.bozo_exception}"
                )
            self.diagnostics.append(
                f"feed parser reported a recoverable error; results may be incomplete: "
                f"{parsed.bozo_exception}"
            )

        articles: list[ParsedArticle] = []
        for entry in parsed.entries:
            published, date_warning = _entry_datetime(entry)
            if published is None:
                self.diagnostics.append(
                    f"skipped entry with missing or invalid publication date: "
                    f"{_clean_text(entry.get('title', '(untitled)'))}"
                )
                continue
            if date_warning:
                self.diagnostics.append(
                    f"{date_warning}: {_clean_text(entry.get('title', '(untitled)'))}"
                )
            if not (since <= published < until):
                continue
            title = _clean_text(entry.get("title", ""))
            url = entry.get("link", "")
            if not title or not url:
                self.diagnostics.append("skipped entry with missing title or URL")
                continue

            excerpt = _clean_text(entry.get("summary", "")) or None
            try:
                body, method, warnings = self._entry_or_html_body(
                    entry,
                    url,
                    title,
                    source.article_selectors,
                    source.article_hosts,
                    source.min_body_characters,
                )
            except ParseError as error:
                body = ""
                method = "failed"
                warnings = [
                    "full article extraction failed; feed excerpt is metadata only",
                    str(error),
                ]
            articles.append(
                ParsedArticle(
                    source=source.name,
                    title=title,
                    url=url,
                    published_at=published.isoformat(),
                    body=body,
                    extraction_method=method,
                    body_characters=len(body),
                    warnings=warnings,
                    feed_excerpt=excerpt,
                    publisher_hosts=source.article_hosts,
                )
            )
            if limit is not None and len(articles) >= limit:
                break
        return articles

    def _entry_or_html_body(
        self,
        entry: Any,
        url: str,
        title: str,
        selectors: tuple[str, ...],
        allowed_hosts: tuple[str, ...],
        min_body_characters: int,
    ) -> tuple[str, str, list[str]]:
        feed_candidates: list[tuple[str, str]] = []
        for item in entry.get("content", []):
            if item.get("value"):
                feed_candidates.append(
                    ("feed:content", _clean_body_text(item["value"]))
                )
        if entry.get("summary"):
            feed_candidates.append(
                ("feed:summary", _clean_body_text(entry["summary"]))
            )

        valid_feed_candidates: list[tuple[str, str, list[str]]] = []
        for method, body in feed_candidates:
            valid, warnings = _looks_like_body(body, title, min_body_characters)
            if valid:
                valid_feed_candidates.append((method, body, warnings))
        complete = [item for item in valid_feed_candidates if len(item[1]) >= 1200]
        if complete:
            method, body, warnings = max(complete, key=lambda item: len(item[1]))
            return body, method, warnings

        try:
            body, method, warnings = self.extract_html(
                url,
                expected_title=title,
                selectors=selectors,
                allowed_hosts=allowed_hosts,
                min_body_characters=min_body_characters,
            )
        except ParseError:
            if valid_feed_candidates:
                method, body, warnings = max(
                    valid_feed_candidates, key=lambda item: len(item[1])
                )
                return (
                    body,
                    f"{method}:partial",
                    [
                        "raw HTML fallback failed; using validated but incomplete feed content",
                        *warnings,
                    ],
                )
            raise
        if feed_candidates:
            warnings.insert(0, "feed content was incomplete; raw HTML fallback used")
        return body, method, warnings


def _entry_datetime(entry: Any) -> tuple[datetime | None, str | None]:
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if struct:
        try:
            return datetime(*struct[:6], tzinfo=timezone.utc), None
        except (TypeError, ValueError, OverflowError):
            pass
    raw = entry.get("published") or entry.get("updated")
    if raw:
        try:
            value = parsedate_to_datetime(raw)
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
                return (
                    value.astimezone(timezone.utc),
                    "publication date lacked a timezone and was treated as UTC",
                )
            return value.astimezone(timezone.utc), None
        except (TypeError, ValueError, OverflowError):
            pass
    return None, None


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def default_window(hours: int, now: datetime | None = None) -> tuple[datetime, datetime]:
    until = now or datetime.now(timezone.utc)
    return until - timedelta(hours=hours), until


def source_key_for_url(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    for key, source in SOURCES.items():
        if _host_allowed(host, source.article_hosts):
            return key
    return ""
