from urllib.parse import urlparse

from soc_news_parser.parser import source_key_for_url
from soc_news_parser.sources import SOURCES


def test_source_registry_has_https_feeds_and_article_allowlists() -> None:
    assert len(SOURCES) == 26
    for key, source in SOURCES.items():
        parsed = urlparse(source.feed_url)
        assert parsed.scheme == "https", key
        assert parsed.hostname, key
        assert source.article_hosts, key
        assert all(host == host.lower() and "/" not in host for host in source.article_hosts)


def test_new_source_article_hosts_resolve_to_registry_keys() -> None:
    examples = {
        "https://securelist.com/example": "securelist",
        "https://www.sentinelone.com/labs/example": "sentinellabs",
        "https://www.proofpoint.com/us/blog/example": "proofpoint",
        "https://isc.sans.edu/diary/example": "sans-isc",
        "https://research.checkpoint.com/example": "check-point",
        "https://www.cisa.gov/news-events/example": "cisa-advisories",
        "https://www.twcert.org.tw/tw/example": "twcert-tvn",
        "https://www.hkcert.org/security-bulletin/example": "hkcert",
        "https://cybersecuritynews.com/fake-microsoft-security-scan/": "cyber-security-news",
    }
    for url, expected in examples.items():
        assert source_key_for_url(url) == expected
