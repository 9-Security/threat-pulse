import hashlib
from datetime import datetime, timezone

from soc_news_parser.evidence import build_manifest
from soc_news_parser.parser import ParsedArticle


def article_with_mixed_evidence() -> ParsedArticle:
    body = """Threat campaign report
Researchers observed example.org in a screenshot, but did not characterize it.
Command and Control to gitnow[.]dev; detection Trojan:Python/Indigo.SA.
The signed trusted.exe loaded a malicious payload.
Indicators of Compromise (IoCs)
File indicators
18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f
Initial ZIP archive (verify_pkg.zip)
Network indicators
gitnow[.]dev
C2 server for custom reverse tunnel implant on port 443.
hxxps://linked-log[.]com/
Compromised website.
Learn more
Read the publisher documentation at hxxps://news.example.test/security.
Related Articles
Another report discusses unrelated.example.com and sample.exe.
"""
    return ParsedArticle(
        source="Example Security",
        title="Threat campaign report",
        url="https://news.example.test/threat-report",
        published_at="2026-08-29T03:43:27+00:00",
        body=body,
        extraction_method="site-selector:article",
        body_characters=len(body),
        warnings=[],
    )


def test_evidence_manifest_is_reproducible_and_challengeable() -> None:
    article = article_with_mixed_evidence()
    manifest = build_manifest(
        article, retrieved_at=datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    )

    confirmed = [item for item in manifest.evidence if item.status == "confirmed"]
    rejected = [item for item in manifest.evidence if item.status == "rejected"]
    candidates = [item for item in manifest.evidence if item.status == "candidate"]

    assert manifest.body_sha256 == hashlib.sha256(article.body.encode()).hexdigest()
    assert manifest.retrieved_at == "2026-08-30T01:21:00+00:00"
    assert any(item.indicator_type == "sha256" for item in confirmed)
    assert any(item.normalized_value == "gitnow.dev" for item in confirmed)
    assert any(item.normalized_value == "https://linked-log.com/" for item in confirmed)
    assert any(item.normalized_value == "example.org" for item in candidates)
    assert any(item.normalized_value == "trusted.exe" for item in candidates)
    assert not any(item.normalized_value == "indigo.sa" for item in manifest.evidence)
    assert any(item.normalized_value == "unrelated.example.com" for item in rejected)
    assert any("excluded_editorial_section" in item.reason_codes for item in rejected)
    assert all(item.context and item.line_number > 0 for item in manifest.evidence)
    assert (
        manifest.unique_counts_by_status_and_type["confirmed"]["total"]
        == manifest.confirmed_unique_iocs
    )
    assert manifest.unique_counts_by_status_and_type["confirmed"]["sha256"] == 1


def test_publisher_domain_is_rejected() -> None:
    article = article_with_mixed_evidence()
    manifest = build_manifest(article)
    publisher = [
        item
        for item in manifest.evidence
        if item.normalized_value == "https://news.example.test/security"
    ]

    assert len(publisher) == 1
    assert publisher[0].status == "rejected"
    assert publisher[0].reason_codes == ["excluded_editorial_section"]
