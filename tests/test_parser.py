from datetime import datetime, timezone

import httpx
import pytest

from soc_news_parser.parser import NewsParser, ParseError
from soc_news_parser.sources import Source


def client_for(routes: dict[str, tuple[str, str]]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        content_type, body = routes[str(request.url)]
        return httpx.Response(
            200,
            headers={"content-type": content_type},
            text=body,
            request=request,
        )

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_feed_summary_falls_back_to_site_parser() -> None:
    feed_url = "https://example.test/feed"
    article_url = "https://example.test/story"
    feed = f"""<?xml version="1.0"?>
    <rss version="2.0"><channel><title>Test</title>
      <item><title>Malware campaign technical analysis</title>
      <link>{article_url}</link>
      <pubDate>Sat, 29 Aug 2026 03:43:27 +0000</pubDate>
      <description>Short summary only.</description></item>
    </channel></rss>"""
    paragraphs = "".join(
        f"<p>Malware campaign technical analysis paragraph {number}: "
        f"{'validated technical detail ' * 12}</p>"
        for number in range(6)
    )
    page = f"<html><body><article><h1>Malware campaign technical analysis</h1>{paragraphs}</article></body></html>"
    parser = NewsParser()
    parser.client.close()
    parser.client = client_for(
        {
            feed_url: ("application/rss+xml", feed),
            article_url: ("text/html", page),
        }
    )

    with parser:
        articles = parser.parse_feed(
            Source("Test", feed_url, ("article",)),
            since=datetime(2026, 8, 29, 0, tzinfo=timezone.utc),
            until=datetime(2026, 8, 30, 0, tzinfo=timezone.utc),
        )

    assert len(articles) == 1
    assert articles[0].extraction_method == "site-selector:article"
    assert articles[0].body_characters > 500
    assert "feed content was incomplete" in articles[0].warnings[0]


def test_json_ld_article_body_is_used() -> None:
    url = "https://example.test/json-ld-story"
    body = "Threat report body. " * 80
    page = f"""<html><head><script type="application/ld+json">
    {{"@type":"NewsArticle","articleBody":{body!r}}}
    </script></head><body><main>Navigation only</main></body></html>"""
    page = page.replace("'", '"')
    parser = NewsParser()
    parser.client.close()
    parser.client = client_for({url: ("text/html", page)})

    with parser:
        extracted, method, _ = parser.extract_html(url)

    assert method == "json-ld:articleBody"
    assert extracted.startswith("Threat report body")


def test_anti_bot_page_is_rejected() -> None:
    url = "https://example.test/challenge"
    page = (
        "<html><body><main><h1>Performing security verification</h1>"
        + "<p>Enable JavaScript and cookies to continue.</p>" * 100
        + "</main></body></html>"
    )
    parser = NewsParser()
    parser.client.close()
    parser.client = client_for({url: ("text/html", page)})

    with parser, pytest.raises(ParseError, match="anti-bot"):
        parser.extract_html(url)


def test_blocked_article_is_reported_without_using_excerpt_as_body() -> None:
    feed_url = "https://example.test/feed"
    article_url = "https://example.test/blocked"
    feed = f"""<?xml version="1.0"?>
    <rss version="2.0"><channel><title>Test</title>
      <item><title>Blocked technical report</title>
      <link>{article_url}</link>
      <pubDate>Sat, 29 Aug 2026 03:43:27 +0000</pubDate>
      <description>This is only a feed excerpt, not the full report.</description></item>
    </channel></rss>"""

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == feed_url:
            return httpx.Response(200, text=feed, request=request)
        return httpx.Response(403, text="Access denied", request=request)

    parser = NewsParser()
    parser.client.close()
    parser.client = httpx.Client(transport=httpx.MockTransport(handler))

    with parser:
        articles = parser.parse_feed(
            Source("Test", feed_url),
            since=datetime(2026, 8, 29, 0, tzinfo=timezone.utc),
            until=datetime(2026, 8, 30, 0, tzinfo=timezone.utc),
        )

    assert articles[0].extraction_method == "failed"
    assert articles[0].body == ""
    assert articles[0].feed_excerpt == "This is only a feed excerpt, not the full report."
    assert "403 Forbidden" in articles[0].warnings[1]
