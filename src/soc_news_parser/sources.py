from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    name: str
    feed_url: str
    article_selectors: tuple[str, ...] = ()


SOURCES: dict[str, Source] = {
    "the-hacker-news": Source(
        "The Hacker News",
        "https://feeds.feedburner.com/TheHackersNews",
        ("div.articlebody", "div[itemprop='articleBody']", "article"),
    ),
    "bleepingcomputer": Source(
        "BleepingComputer",
        "https://www.bleepingcomputer.com/feed/",
        ("div.articleBody", "div.article_body", "article"),
    ),
    "krebs": Source(
        "Krebs on Security",
        "https://krebsonsecurity.com/feed/",
        ("div.entry-content", "article"),
    ),
    "dark-reading": Source(
        "Dark Reading",
        "https://www.darkreading.com/rss.xml",
        ("div.article-content", "div.article-body", "main article", "article"),
    ),
    "securityweek": Source(
        "SecurityWeek",
        "https://www.securityweek.com/feed/",
        ("div.entry-content", "div.article-content", "article"),
    ),
    "the-record": Source(
        "The Record",
        "https://therecord.media/feed/",
        ("div.article-body", "div.entry-content", "article"),
    ),
    "unit42": Source(
        "Unit 42",
        "https://unit42.paloaltonetworks.com/feed/",
        ("div.entry-content", "div.article-content", "article"),
    ),
    "cisco-talos": Source(
        "Cisco Talos",
        "https://blog.talosintelligence.com/rss/",
        ("div.gh-content", "article"),
    ),
    "microsoft-security": Source(
        "Microsoft Security Blog",
        "https://www.microsoft.com/en-us/security/blog/feed/",
        ("div.entry-content", "main article", "article"),
    ),
    "google-mandiant": Source(
        "Google Cloud/Mandiant",
        "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
        ("div.article-content", "main article", "article"),
    ),
}
