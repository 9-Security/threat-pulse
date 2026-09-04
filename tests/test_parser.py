import json
from datetime import datetime, timezone

import httpx
import pytest
from bs4 import BeautifulSoup

from soc_news_parser.parser import (
    MAX_JSON_LD_NODES,
    NewsParser,
    ParseError,
    _entry_datetime,
    _json_ld_candidates,
)
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

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def news_parser() -> NewsParser:
    return NewsParser(resolver=lambda _: ["93.184.216.34"])


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
    parser = news_parser()
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
    parser = news_parser()
    parser.client.close()
    parser.client = client_for({url: ("text/html", page)})

    with parser:
        extracted, method, _ = parser.extract_html(url)

    assert method == "json-ld:articleBody"
    assert extracted.startswith("Threat report body")


def test_feed_keeps_all_in_window_articles_from_one_source() -> None:
    feed_url = "https://example.test/feed"
    items = []
    routes: dict[str, tuple[str, str]] = {}
    for hour, slug in ((8, "one"), (12, "two"), (16, "three")):
        article_url = f"https://example.test/{slug}"
        items.append(
            f"<item><title>Story {slug}</title><link>{article_url}</link>"
            f"<pubDate>Sat, 29 Aug 2026 {hour:02d}:00:00 +0000</pubDate>"
            f"<description>Short.</description></item>"
        )
        routes[article_url] = (
            "text/html",
            "<html><body><article><h1>Story "
            + slug
            + "</h1>"
            + "".join(
                f"<p>Malware campaign technical analysis paragraph {number}: "
                f"{'validated technical detail ' * 12}</p>"
                for number in range(6)
            )
            + "</article></body></html>",
        )
    routes[feed_url] = (
        "application/rss+xml",
        '<?xml version="1.0"?><rss version="2.0"><channel><title>Test</title>'
        + "".join(items)
        + "</channel></rss>",
    )
    parser = news_parser()
    parser.client.close()
    parser.client = client_for(routes)

    with parser:
        articles = parser.parse_feed(
            Source("Test", feed_url, ("article",), ("example.test",)),
            since=datetime(2026, 8, 29, 0, tzinfo=timezone.utc),
            until=datetime(2026, 8, 30, 0, tzinfo=timezone.utc),
        )

    assert [item.url for item in articles] == [
        "https://example.test/one",
        "https://example.test/two",
        "https://example.test/three",
    ]


def test_anti_bot_page_is_rejected() -> None:
    url = "https://example.test/challenge"
    page = (
        "<html><body><main><h1>Performing security verification</h1>"
        + "<p>Enable JavaScript and cookies to continue.</p>" * 100
        + "</main></body></html>"
    )
    parser = news_parser()
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

    parser = news_parser()
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


def test_redirect_to_private_address_is_rejected() -> None:
    url = "https://example.test/story"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://127.0.0.1/latest/meta-data"},
            request=request,
        )

    parser = news_parser()
    parser.client.close()
    parser.client = httpx.Client(transport=httpx.MockTransport(handler))

    with parser, pytest.raises(ParseError, match="non-public"):
        parser.extract_html(
            url, allowed_hosts=("example.test", "127.0.0.1")
        )


def test_valid_partial_feed_body_is_retained_when_html_is_blocked() -> None:
    feed_url = "https://example.test/feed"
    article_url = "https://example.test/blocked"
    partial = "Technical report paragraph. " * 25
    feed = f"""<rss version="2.0"><channel><title>Test</title>
    <item><title>Technical report</title><link>{article_url}</link>
    <pubDate>Sat, 29 Aug 2026 03:43:27 +0000</pubDate>
    <description>{partial}</description></item></channel></rss>"""

    def handler(request: httpx.Request) -> httpx.Response:
        status = 200 if str(request.url) == feed_url else 403
        return httpx.Response(status, text=feed if status == 200 else "", request=request)

    parser = news_parser()
    parser.client.close()
    parser.client = httpx.Client(transport=httpx.MockTransport(handler))

    with parser:
        articles = parser.parse_feed(
            Source("Test", feed_url, article_hosts=("example.test",)),
            since=datetime(2026, 8, 29, 0, tzinfo=timezone.utc),
            until=datetime(2026, 8, 30, 0, tzinfo=timezone.utc),
        )

    assert articles[0].extraction_method == "feed:summary:partial"
    assert articles[0].body.startswith("Technical report paragraph")
    assert "incomplete feed content" in articles[0].warnings[0]


def test_complete_feed_content_preserves_body_and_method_order() -> None:
    feed_url = "https://example.test/feed"
    article_url = "https://example.test/story"
    content = "Complete technical article body. " * 60
    feed = f"""<rss version="2.0"
    xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
    <title>Test</title><item><title>Complete technical article</title>
    <link>{article_url}</link>
    <pubDate>Sat, 29 Aug 2026 03:43:27 +0000</pubDate>
    <content:encoded><![CDATA[<p>{content}</p>]]></content:encoded>
    </item></channel></rss>"""
    parser = news_parser()
    parser.client.close()
    parser.client = client_for({feed_url: ("application/rss+xml", feed)})

    with parser:
        articles = parser.parse_feed(
            Source("Test", feed_url),
            since=datetime(2026, 8, 29, 0, tzinfo=timezone.utc),
            until=datetime(2026, 8, 30, 0, tzinfo=timezone.utc),
        )

    assert articles[0].extraction_method == "feed:content"
    assert articles[0].body.startswith("Complete technical article body")


def test_article_discussing_access_denied_is_not_rejected() -> None:
    url = "https://example.test/story"
    paragraphs = "".join(
        f"<p>Analysis paragraph {index} discusses an Access Denied response "
        f"without being a challenge page. {'detail ' * 30}</p>"
        for index in range(5)
    )
    parser = news_parser()
    parser.client.close()
    parser.client = client_for(
        {url: ("text/html", f"<article>{paragraphs}</article>")}
    )

    with parser:
        body, _, _ = parser.extract_html(url)

    assert "Access Denied" in body


def test_source_host_mismatch_is_rejected_before_fetch() -> None:
    parser = news_parser()
    with parser, pytest.raises(ParseError, match="not allowed"):
        parser.extract_html(
            "https://unrelated.example/story",
            allowed_hosts=("microsoft.com",),
        )


def test_missing_entry_date_is_exposed_as_diagnostic() -> None:
    feed_url = "https://example.test/feed"
    feed = """<rss version="2.0"><channel><title>Test</title>
    <item><title>Undated report</title><link>https://example.test/story</link>
    </item></channel></rss>"""
    parser = news_parser()
    parser.client.close()
    parser.client = client_for({feed_url: ("application/rss+xml", feed)})

    with parser:
        articles = parser.parse_feed(
            Source("Test", feed_url),
            since=datetime(2026, 8, 29, 0, tzinfo=timezone.utc),
            until=datetime(2026, 8, 30, 0, tzinfo=timezone.utc),
        )

    assert articles == []
    assert "missing or invalid publication date" in parser.diagnostics[0]


def test_naive_publication_date_is_treated_as_utc() -> None:
    when, warning = _entry_datetime({"published": "Sat, 29 Aug 2026 12:00:00"})

    assert when == datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
    assert warning is not None
    assert "timezone" in warning


def test_json_ld_graph_is_capped() -> None:
    nested: dict[str, object] = {}
    for _ in range(200):
        nested = {"@graph": [nested]}
    page = (
        '<html><head><script type="application/ld+json">'
        f"{json.dumps(nested)}"
        "</script></head><body></body></html>"
    )
    bodies = list(_json_ld_candidates(BeautifulSoup(page, "lxml")))

    assert bodies == []


def test_json_ld_still_reads_root_article_body() -> None:
    payload = {
        "articleBody": "Threat report body. " * 80,
        "@graph": [{"name": str(index)} for index in range(MAX_JSON_LD_NODES * 2)],
    }
    page = (
        '<html><head><script type="application/ld+json">'
        f"{json.dumps(payload)}"
        "</script></head><body></body></html>"
    )
    bodies = list(_json_ld_candidates(BeautifulSoup(page, "lxml")))

    assert bodies[0].startswith("Threat report body")


def test_request_headers_are_dropped_when_a_redirect_leaves_the_host() -> None:
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("apikey")))
        if request.url.host == "api.example.test":
            return httpx.Response(
                302,
                headers={"location": "https://mirror.other.test/v2"},
                request=request,
            )
        return httpx.Response(200, text="{}", request=request)

    parser = news_parser()
    parser.client.close()
    parser.client = httpx.Client(transport=httpx.MockTransport(handler))

    with parser:
        parser._get(
            "https://api.example.test/v1",
            allowed_hosts=("api.example.test", "mirror.other.test"),
            headers={"apiKey": "secret-key"},
        )

    assert seen[0] == ("https://api.example.test/v1", "secret-key")
    assert seen[1] == ("https://mirror.other.test/v2", None)


def test_request_headers_survive_a_same_host_redirect() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("apikey"))
        if request.url.path == "/v1":
            return httpx.Response(
                302, headers={"location": "https://api.example.test/v2"}, request=request
            )
        return httpx.Response(200, text="{}", request=request)

    parser = news_parser()
    parser.client.close()
    parser.client = httpx.Client(transport=httpx.MockTransport(handler))

    with parser:
        parser._get(
            "https://api.example.test/v1",
            allowed_hosts=("api.example.test",),
            headers={"apiKey": "secret-key"},
        )

    assert seen == ["secret-key", "secret-key"]
