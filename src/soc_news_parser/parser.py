from __future__ import annotations

import html
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable
from urllib.parse import urlparse

import feedparser
import httpx
import trafilatura
from bs4 import BeautifulSoup, Tag

from .sources import Source


USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0 Safari/537.36 "
    "SOC-News-Parser/0.1"
)
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _clean_text(value: str) -> str:
    value = BeautifulSoup(html.unescape(value), "lxml").get_text("\n")
    value = value.replace("\xa0", " ")
    lines = (re.sub(r"[ \t]+", " ", line).strip() for line in value.splitlines())
    return "\n".join(line for line in lines if line)


def _looks_like_body(text: str, expected_title: str = "") -> tuple[bool, list[str]]:
    warnings: list[str] = []
    lowered = text.lower()
    if any(marker in lowered for marker in BLOCK_PAGE_MARKERS):
        return False, ["anti-bot or access-denied page detected"]
    if len(text) < 500:
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
    for node in clone.select("h1, h2, h3, h4, p, li, pre, blockquote, tr"):
        text = " ".join(node.stripped_strings)
        if text and (not blocks or blocks[-1] != text):
            blocks.append(text)
    return "\n".join(blocks) if blocks else _clean_text(clone.get_text("\n"))


def _json_ld_candidates(soup: BeautifulSoup) -> Iterable[str]:
    for script in soup.select("script[type='application/ld+json']"):
        raw = script.string or script.get_text()
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        queue = payload if isinstance(payload, list) else [payload]
        for item in queue:
            if isinstance(item, dict) and isinstance(item.get("@graph"), list):
                queue.extend(item["@graph"])
            if isinstance(item, dict) and isinstance(item.get("articleBody"), str):
                yield _clean_text(item["articleBody"])


class NewsParser:
    def __init__(self, timeout: float = 25.0) -> None:
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/rss+xml,"
                "application/atom+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8,zh-TW;q=0.7",
            },
        )

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> NewsParser:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _get(self, url: str) -> httpx.Response:
        try:
            response = self.client.get(url)
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise ParseError(f"HTTP fetch failed for {url}: {error}") from error
        if len(response.content) > 12 * 1024 * 1024:
            raise ParseError(f"response exceeds 12 MiB: {url}")
        return response

    def extract_html(
        self,
        url: str,
        *,
        expected_title: str = "",
        selectors: tuple[str, ...] = (),
    ) -> tuple[str, str, list[str]]:
        response = self._get(url)
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
        )
        if extracted:
            attempts.append(("trafilatura", extracted))

        for selector in ("article", "main", "[role='main']"):
            node = soup.select_one(selector)
            if node:
                attempts.append((f"semantic-selector:{selector}", _tag_text(node)))

        failures: list[str] = []
        for method, candidate in attempts:
            body = _clean_text(candidate)
            valid, warnings = _looks_like_body(body, expected_title)
            if valid:
                return body, method, warnings
            failures.append(f"{method}: {', '.join(warnings)}")
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
        response = self._get(source.feed_url)
        parsed = feedparser.parse(response.content)
        if parsed.bozo and not parsed.entries:
            raise ParseError(f"invalid feed {source.feed_url}: {parsed.bozo_exception}")

        articles: list[ParsedArticle] = []
        for entry in parsed.entries:
            published = _entry_datetime(entry)
            if published is None or not (since <= published < until):
                continue
            title = _clean_text(entry.get("title", ""))
            url = entry.get("link", "")
            if not title or not url:
                continue

            excerpt = _clean_text(entry.get("summary", "")) or None
            try:
                body, method, warnings = self._entry_or_html_body(
                    entry, url, title, source.article_selectors
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
    ) -> tuple[str, str, list[str]]:
        feed_candidates: list[tuple[str, str]] = []
        for item in entry.get("content", []):
            if item.get("value"):
                feed_candidates.append(("feed:content", _clean_text(item["value"])))
        if entry.get("summary"):
            feed_candidates.append(("feed:summary", _clean_text(entry["summary"])))

        for method, body in feed_candidates:
            valid, warnings = _looks_like_body(body, title)
            if valid and len(body) >= 1200:
                return body, method, warnings

        body, method, warnings = self.extract_html(
            url, expected_title=title, selectors=selectors
        )
        if feed_candidates:
            warnings.insert(0, "feed content was incomplete; raw HTML fallback used")
        return body, method, warnings


def _entry_datetime(entry: Any) -> datetime | None:
    raw = entry.get("published") or entry.get("updated")
    if raw:
        try:
            value = parsedate_to_datetime(raw)
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            pass
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if struct:
        return datetime(*struct[:6], tzinfo=timezone.utc)
    return None


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def default_window(hours: int, now: datetime | None = None) -> tuple[datetime, datetime]:
    until = now or datetime.now(timezone.utc)
    return until - timedelta(hours=hours), until


def source_key_for_url(url: str) -> str:
    host = urlparse(url).hostname or ""
    aliases = {
        "thehackernews.com": "the-hacker-news",
        "www.bleepingcomputer.com": "bleepingcomputer",
        "krebsonsecurity.com": "krebs",
        "www.darkreading.com": "dark-reading",
        "www.securityweek.com": "securityweek",
        "therecord.media": "the-record",
        "unit42.paloaltonetworks.com": "unit42",
        "blog.talosintelligence.com": "cisco-talos",
        "www.microsoft.com": "microsoft-security",
        "cloud.google.com": "google-mandiant",
    }
    return aliases.get(host, "")
