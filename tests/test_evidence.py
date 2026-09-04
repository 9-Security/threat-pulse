import hashlib
from datetime import datetime, timezone

from soc_news_parser.evidence import COUNTED_IOC_TYPES, build_manifest
from soc_news_parser.parser import ParsedArticle


def article_with_mixed_evidence() -> ParsedArticle:
    body = """Threat campaign report
Researchers observed example.org in a screenshot, but did not characterize it.
Publisher portal: hxxps://news.example.test/about.
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
        publisher_hosts=("example.test",),
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
    assert manifest.canonical_body == article.body
    assert manifest.extraction_warnings == []
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
    counted_confirmed = sum(
        count
        for key, count in manifest.unique_counts_by_status_and_type["confirmed"].items()
        if key in COUNTED_IOC_TYPES
    )
    assert manifest.confirmed_unique_iocs == counted_confirmed
    assert manifest.unique_counts_by_status_and_type["confirmed"]["sha256"] == 1
    assert manifest.unique_counts_by_status_and_type["confirmed"]["filename"] == 1
    assert manifest.confirmed_unique_iocs == 3


def test_publisher_domain_is_rejected() -> None:
    article = article_with_mixed_evidence()
    manifest = build_manifest(article)
    publisher = [
        item
        for item in manifest.evidence
        if item.normalized_value == "https://news.example.test/about"
    ]

    assert len(publisher) == 1
    assert publisher[0].status == "rejected"
    assert publisher[0].reason_codes == ["publisher_domain"]


def test_heading_boundaries_reset_ioc_and_excluded_zones() -> None:
    body = """## Indicators of Compromise
evil[.]example.com
## Analysis
analysis.example.com
## References
reference.example.com
## Technical details
technical.example.com
"""
    article = article_with_mixed_evidence()
    article.body = body
    manifest = build_manifest(article)
    statuses = {
        item.normalized_value: item.status
        for item in manifest.evidence
        if item.indicator_type == "domain"
    }

    assert statuses == {
        "evil.example.com": "confirmed",
        "analysis.example.com": "candidate",
        "reference.example.com": "rejected",
        "technical.example.com": "candidate",
    }


def test_url_path_case_ipv6_and_occurrence_ids_are_preserved() -> None:
    body = """## Indicators of Compromise
hxxps://evil[.]example.com/CaseToken
hxxps://evil[.]example.com/casetoken
2001:4860:4860::8888
repeat.example.com repeat.example.com
"""
    article = article_with_mixed_evidence()
    article.body = body
    manifest = build_manifest(article)
    values = [item.normalized_value for item in manifest.evidence]
    repeat_ids = [
        item.evidence_id
        for item in manifest.evidence
        if item.normalized_value == "repeat.example.com"
    ]

    assert "https://evil.example.com/CaseToken" in values
    assert "https://evil.example.com/casetoken" in values
    assert "2001:4860:4860::8888" in values
    assert len(repeat_ids) == 2
    assert len(set(repeat_ids)) == 2


def test_explicit_cves_and_quoted_claims_are_confirmed() -> None:
    body = """Vulnerability analysis
Researchers tracked the malware family named LockBit and the LockBit ransomware.
Operators used MITRE ATT&CK technique T1059.001.
Standalone T1027 should not count.
A feature called Email Aliases is not malware.
CVE-2026-76581 and cve-2026-18431 are listed.
(Affects all versions up to, and including, 4.16.7.1)
The C2 server 185.199.108.153 remains unconfirmed.
    Related : ATF Confirms Cyber Incident After Ransomware Group Claims Attack
    Related Articles
CVE-2024-0001 is only in an editorial list.
"""
    article = article_with_mixed_evidence()
    article.body = body
    manifest = build_manifest(article)
    confirmed = {
        (item.indicator_type, item.normalized_value)
        for item in manifest.evidence
        if item.status == "confirmed"
    }
    rejected = {
        item.normalized_value
        for item in manifest.evidence
        if item.status == "rejected"
    }
    values = {item.normalized_value for item in manifest.evidence}

    assert ("cve", "CVE-2026-76581") in confirmed
    assert ("cve", "CVE-2026-18431") in confirmed
    assert ("malware_family", "LockBit") in confirmed
    assert ("attack_technique", "T1059.001") in confirmed
    assert "T1027" not in values
    assert "Email Aliases" not in values
    assert "After" not in values
    assert "4.16.7.1" not in values
    assert "CVE-2024-0001" in rejected
    ip = next(item for item in manifest.evidence if item.normalized_value == "185.199.108.153")
    assert ip.status == "candidate"


def test_private_ip_is_rejected_even_in_ioc_section() -> None:
    body = """## Indicators of Compromise
127.0.0.1
10.0.0.8
185.199.108.153
"""
    article = article_with_mixed_evidence()
    article.body = body
    manifest = build_manifest(article)
    evidence = {item.normalized_value: item for item in manifest.evidence}

    assert evidence["127.0.0.1"].status == "rejected"
    assert evidence["127.0.0.1"].reason_codes == ["non_public_ip"]
    assert evidence["10.0.0.8"].reason_codes == ["non_public_ip"]
    assert evidence["185.199.108.153"].status == "confirmed"


def test_chinese_ioc_heading_confirms_network_indicators() -> None:
    body = """威脅分析
妥協指標
evil[.]example.com
相關文章
sidebar.example.com
"""
    article = article_with_mixed_evidence()
    article.body = body
    manifest = build_manifest(article)
    statuses = {
        item.normalized_value: item.status
        for item in manifest.evidence
        if item.indicator_type == "domain"
    }

    assert statuses["evil.example.com"] == "confirmed"
    assert statuses["sidebar.example.com"] == "rejected"


def test_technique_without_attack_framework_is_not_extracted() -> None:
    body = """Analysis
Operators used the technique T1055 during injection.
MITRE ATT&CK T1059.001 was named explicitly.
"""
    article = article_with_mixed_evidence()
    article.body = body
    manifest = build_manifest(article)
    techniques = {
        item.normalized_value
        for item in manifest.evidence
        if item.indicator_type == "attack_technique"
    }

    assert techniques == {"T1059.001"}


def test_negated_inline_indicator_and_document_are_not_confirmed_domains() -> None:
    body = """## Analysis
This is not an IoC: benign.example.com.
The malicious file is invoice.docx.
Payload delivery domain bestsocialmedianewspapper.com serves an archive.
"""
    article = article_with_mixed_evidence()
    article.body = body
    manifest = build_manifest(article)
    evidence = {item.normalized_value: item for item in manifest.evidence}

    assert evidence["benign.example.com"].status == "candidate"
    assert evidence["invoice.docx"].indicator_type == "filename"
    assert evidence["invoice.docx"].status == "candidate"
    assert evidence["bestsocialmedianewspapper.com"].indicator_type == "domain"


def test_markdown_ioc_heading_noise_still_confirms_section_values() -> None:
    article = article_with_mixed_evidence()
    article.body = """The scam sites collect browser information.
Indicators of compromise (IoCs):-**
| Type | Indicator | Description |
| IP address | `157.230.180.90` | Hosting server |
| Domain | `detectsysscanner[.]at` | Scam site |
| Domain | `detectsysscanner[.]xn--q9jyb4c` | IDN scam site |
## Analysis
later.example.com
"""
    manifest = build_manifest(article)
    by_value = {item.normalized_value: item for item in manifest.evidence}

    assert by_value["157.230.180.90"].status == "confirmed"
    assert by_value["detectsysscanner.at"].status == "confirmed"
    assert by_value["detectsysscanner.xn--q9jyb4c"].status == "confirmed"
    assert by_value["later.example.com"].status == "candidate"


def test_prose_mention_of_iocs_is_not_a_heading() -> None:
    article = article_with_mixed_evidence()
    article.body = """The report lists indicators of compromise below.
prose.example.com
"""
    manifest = build_manifest(article)
    by_value = {item.normalized_value: item for item in manifest.evidence}

    assert by_value["prose.example.com"].status == "candidate"



def test_payload_file_extensions_are_not_blockable_domains() -> None:
    article = article_with_mixed_evidence()
    article.body = """Indicators of compromise (IoCs):-**
File names out.tmp ; out.enc ; user.enc ; acc.enc ; combo.enc
File names runner.ps1 ; sys_cache.zip
Network indicators
borertors92[.]anondns[.]net
"""
    manifest = build_manifest(article)
    by_value = {item.normalized_value: item for item in manifest.evidence}

    for name in ("out.tmp", "out.enc", "user.enc", "acc.enc", "combo.enc"):
        assert by_value[name].indicator_type == "filename"
    assert by_value["runner.ps1"].indicator_type == "filename"
    assert by_value["borertors92.anondns.net"].indicator_type == "domain"
    assert by_value["borertors92.anondns.net"].status == "confirmed"
    assert manifest.unique_counts_by_status_and_type["confirmed"].get("domain") == 1


def test_dotted_tokens_without_a_real_tld_are_not_domains() -> None:
    article = article_with_mixed_evidence()
    article.body = """Indicators of Compromise
robots.txt
system.drawing.bitmap
ntds.dit
win.dropper.miner
gitnow[.]dev
"""
    manifest = build_manifest(article)
    domains = {
        item.normalized_value
        for item in manifest.evidence
        if item.indicator_type == "domain"
    }

    assert domains == {"gitnow.dev"}


def test_plural_file_name_lead_reclassifies_an_unlisted_extension() -> None:
    article = article_with_mixed_evidence()
    article.body = """Indicators of Compromise
File names stage2.shellcode
"""
    manifest = build_manifest(article)
    by_value = {item.normalized_value: item for item in manifest.evidence}

    assert by_value["stage2.shellcode"].indicator_type == "filename"
