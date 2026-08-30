from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    name: str
    feed_url: str
    article_selectors: tuple[str, ...] = ()
    article_hosts: tuple[str, ...] = ()


SOURCES: dict[str, Source] = {
    "the-hacker-news": Source(
        "The Hacker News",
        "https://feeds.feedburner.com/TheHackersNews",
        ("div.articlebody", "div[itemprop='articleBody']", "article"),
        ("thehackernews.com",),
    ),
    "bleepingcomputer": Source(
        "BleepingComputer",
        "https://www.bleepingcomputer.com/feed/",
        ("div.articleBody", "div.article_body", "article"),
        ("bleepingcomputer.com",),
    ),
    "krebs": Source(
        "Krebs on Security",
        "https://krebsonsecurity.com/feed/",
        ("div.entry-content", "article"),
        ("krebsonsecurity.com",),
    ),
    "dark-reading": Source(
        "Dark Reading",
        "https://www.darkreading.com/rss.xml",
        ("div.article-content", "div.article-body", "main article", "article"),
        ("darkreading.com",),
    ),
    "securityweek": Source(
        "SecurityWeek",
        "https://www.securityweek.com/feed/",
        ("div.entry-content", "div.article-content", "article"),
        ("securityweek.com",),
    ),
    "the-record": Source(
        "The Record",
        "https://therecord.media/feed/",
        ("div.article-body", "div.entry-content", "article"),
        ("therecord.media",),
    ),
    "unit42": Source(
        "Unit 42",
        "https://unit42.paloaltonetworks.com/feed/",
        ("div.entry-content", "div.article-content", "article"),
        ("paloaltonetworks.com",),
    ),
    "cisco-talos": Source(
        "Cisco Talos",
        "https://blog.talosintelligence.com/rss/",
        ("div.gh-content", "article"),
        ("talosintelligence.com",),
    ),
    "microsoft-security": Source(
        "Microsoft Security Blog",
        "https://www.microsoft.com/en-us/security/blog/feed/",
        ("div.entry-content", "main article", "article"),
        ("microsoft.com",),
    ),
    "google-mandiant": Source(
        "Google Cloud/Mandiant",
        "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
        ("div.article-content", "main article", "article"),
        ("cloud.google.com", "withgoogle.com"),
    ),
    "eset": Source(
        "ESET WeLiveSecurity",
        "https://feeds.feedburner.com/eset/blog?format=xml",
        ("div.article-content", "div.entry-content", "main article", "article"),
        ("welivesecurity.com", "eset.com"),
    ),
    "securelist": Source(
        "Securelist by Kaspersky",
        "https://securelist.com/feed/",
        ("div.article__content", "div.entry-content", "main article", "article"),
        ("securelist.com",),
    ),
    "sentinellabs": Source(
        "SentinelLABS",
        "https://www.sentinelone.com/labs/feed/",
        ("div.post-content", "div.entry-content", "main article", "article"),
        ("sentinelone.com",),
    ),
    "proofpoint": Source(
        "Proofpoint Threat Insight",
        "https://www.proofpoint.com/us/threat-insight-blog.xml",
        ("div.field--name-body", "div.article-content", "main article", "article"),
        ("proofpoint.com",),
    ),
    "recorded-future": Source(
        "Recorded Future Insikt Group",
        "https://www.recordedfuture.com/feed",
        ("div.article-body", "div.entry-content", "main article", "article"),
        ("recordedfuture.com",),
    ),
    "sans-isc": Source(
        "SANS Internet Storm Center",
        "https://isc.sans.edu/rssfeed_full.xml",
        ("div#diarybody", "div.diary", "main article", "article"),
        ("isc.sans.edu", "sans.edu"),
    ),
    "dfir-report": Source(
        "The DFIR Report",
        "https://thedfirreport.com/feed/",
        ("div.entry-content", "main article", "article"),
        ("thedfirreport.com",),
    ),
    "elastic-security": Source(
        "Elastic Security Labs",
        "https://www.elastic.co/security-labs/rss/feed.xml",
        ("div.article-content", "main article", "article", "main"),
        ("elastic.co",),
    ),
    "check-point": Source(
        "Check Point Research",
        "https://research.checkpoint.com/feed/",
        ("div.entry-content", "main article", "article"),
        ("checkpoint.com",),
    ),
    "cisa-advisories": Source(
        "CISA Cybersecurity Advisories",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        ("div.l-page-section", "div.field--name-body", "main article", "article"),
        ("cisa.gov",),
    ),
    "watchtowr": Source(
        "watchTowr Labs",
        "https://labs.watchtowr.com/rss/",
        ("div.gh-content", "main article", "article"),
        ("watchtowr.com",),
    ),
    "cert-cc": Source(
        "CERT/CC Vulnerability Notes",
        "https://www.kb.cert.org/vulfeed",
        ("div.vul-note", "main article", "article", "main"),
        ("kb.cert.org", "cert.org"),
    ),
    "twcert-tvn": Source(
        "TWCERT/CC TVN",
        "https://www.twcert.org.tw/tw/rss-132-1.xml",
        ("div.content", "main article", "article", "main"),
        ("twcert.org.tw",),
    ),
    "nics": Source(
        "國家資通安全研究院 NICS",
        "https://www.nics.nat.gov.tw/RSS2.xml",
        ("div.article-content", "main article", "article", "main"),
        ("nics.nat.gov.tw",),
    ),
    "hkcert": Source(
        "HKCERT Security Bulletin",
        "https://www.hkcert.org/getrss/security-bulletin",
        ("div.article-content", "main article", "article", "main"),
        ("hkcert.org",),
    ),
}
