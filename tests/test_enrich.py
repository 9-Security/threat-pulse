import json
from datetime import datetime, timedelta, timezone

from soc_news_parser.analyst import build_brief, render_ioc_csv_from_actions
from soc_news_parser.enrich import (
    KEV_URL,
    NVD_URL,
    CveIntel,
    collect_cve_ids,
    enrich_cves,
)
from soc_news_parser.evidence import build_manifest
from soc_news_parser.parser import ParseError, ParsedArticle

NOW = datetime(2026, 9, 4, 6, 0, tzinfo=timezone.utc)


def kev_payload(*cve_ids: str) -> bytes:
    return json.dumps(
        {
            "catalogVersion": "2026.09.03",
            "dateReleased": "2026-09-03T14:00:00.0000Z",
            "vulnerabilities": [
                {
                    "cveID": cve_id,
                    "dateAdded": "2026-08-14",
                    "dueDate": "2026-09-04",
                    "knownRansomwareCampaignUse": "Known",
                }
                for cve_id in cve_ids
            ],
        }
    ).encode()


def nvd_payload(cve_id: str, score: float | None, severity: str = "CRITICAL") -> bytes:
    metrics = (
        {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": score,
                        "baseSeverity": severity,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        }
        if score is not None
        else {}
    )
    return json.dumps(
        {
            "vulnerabilities": [
                {"cve": {"id": cve_id, "vulnStatus": "Analyzed", "metrics": metrics}}
            ]
        }
    ).encode()


def make_fetcher(responses: dict[str, bytes], calls: list[str] | None = None):
    def fetch(url: str, allowed_hosts: tuple[str, ...], headers):
        if calls is not None:
            calls.append(url)
        for prefix, payload in responses.items():
            if url.startswith(prefix):
                return payload
        raise ParseError(f"unexpected URL {url}")

    return fetch


def article_with_cves(body: str) -> ParsedArticle:
    return ParsedArticle(
        source="Example Security",
        title="Vendor patches an exploited flaw",
        url="https://news.example.test/advisory",
        published_at="2026-09-03T10:00:00+00:00",
        body=body,
        extraction_method="site-selector:article",
        body_characters=len(body),
        warnings=[],
        publisher_hosts=("example.test",),
    )


def test_kev_and_cvss_are_recorded_with_their_own_provenance(tmp_path) -> None:
    fetch = make_fetcher(
        {
            KEV_URL: kev_payload("CVE-2026-1111"),
            f"{NVD_URL}?cveId=CVE-2026-1111": nvd_payload("CVE-2026-1111", 9.8),
            f"{NVD_URL}?cveId=CVE-2026-2222": nvd_payload("CVE-2026-2222", 5.3, "MEDIUM"),
        }
    )
    intel, report = enrich_cves(
        ["CVE-2026-1111", "CVE-2026-2222"],
        fetcher=fetch,
        cache_dir=tmp_path,
        now=NOW,
    )

    exploited = intel["CVE-2026-1111"]
    assert exploited.kev is True
    assert exploited.kev_due_date == "2026-09-04"
    assert exploited.kev_known_ransomware is True
    assert exploited.cvss_score == 9.8
    assert exploited.cvss_severity == "CRITICAL"
    assert exploited.cvss_version == "3.1"
    assert KEV_URL in exploited.sources
    assert exploited.retrieved_at == NOW.isoformat()

    quiet = intel["CVE-2026-2222"]
    assert quiet.kev is False
    assert quiet.cvss_score == 5.3

    assert report.enabled is True
    assert report.kev_count == 1
    assert report.cvss_count == 2
    assert report.kev_catalog_released == "2026-09-03T14:00:00.0000Z"
    assert report.errors == []


def test_a_second_run_on_the_same_day_makes_no_request(tmp_path) -> None:
    calls: list[str] = []
    responses = {
        KEV_URL: kev_payload(),
        f"{NVD_URL}?cveId=CVE-2026-1111": nvd_payload("CVE-2026-1111", 7.5, "HIGH"),
    }
    for _ in range(2):
        enrich_cves(
            ["CVE-2026-1111"],
            fetcher=make_fetcher(responses, calls),
            cache_dir=tmp_path,
            now=NOW,
        )

    assert len(calls) == 2  # one KEV plus one NVD, both from the first run
    _, second = enrich_cves(
        ["CVE-2026-1111"], fetcher=make_fetcher(responses, calls), cache_dir=tmp_path, now=NOW
    )
    assert second.cache_hits == 1
    assert second.lookups == 0


def test_an_unscored_cve_is_rechecked_the_next_day(tmp_path) -> None:
    calls: list[str] = []
    responses = {
        KEV_URL: kev_payload(),
        f"{NVD_URL}?cveId=CVE-2026-3333": nvd_payload("CVE-2026-3333", None),
    }
    enrich_cves(
        ["CVE-2026-3333"],
        fetcher=make_fetcher(responses, calls),
        cache_dir=tmp_path,
        now=NOW,
    )
    _, later = enrich_cves(
        ["CVE-2026-3333"],
        fetcher=make_fetcher(responses, calls),
        cache_dir=tmp_path,
        now=NOW + timedelta(days=1),
    )

    assert later.lookups == 1


def test_a_failed_lookup_is_reported_and_never_raises(tmp_path) -> None:
    def broken(url: str, allowed_hosts: tuple[str, ...], headers):
        raise ParseError("network is down")

    intel, report = enrich_cves(
        ["CVE-2026-4444"], fetcher=broken, cache_dir=tmp_path, now=NOW
    )

    assert intel == {}
    assert report.enabled is True
    assert any("KEV" in item for item in report.errors)
    assert any("CVE-2026-4444" in item for item in report.errors)


def test_rate_limit_waits_before_exceeding_the_nvd_allowance(tmp_path) -> None:
    slept: list[float] = []
    ticks = iter(range(0, 200))
    responses = {KEV_URL: kev_payload()}
    cves = [f"CVE-2026-500{index}" for index in range(6)]
    for cve_id in cves:
        responses[f"{NVD_URL}?cveId={cve_id}"] = nvd_payload(cve_id, 4.0, "MEDIUM")

    enrich_cves(
        cves,
        fetcher=make_fetcher(responses),
        cache_dir=tmp_path,
        now=NOW,
        sleeper=slept.append,
        clock=lambda: float(next(ticks)),
    )

    # Four lookups are free; the fifth has to wait out the 30s window.
    assert slept and all(delay > 0 for delay in slept)


def test_an_api_key_is_sent_to_nvd_only(tmp_path) -> None:
    seen: list[tuple[str, dict | None]] = []

    def fetch(url: str, allowed_hosts: tuple[str, ...], headers):
        seen.append((url, headers))
        if url.startswith(KEV_URL):
            return kev_payload()
        return nvd_payload("CVE-2026-6666", 6.1, "MEDIUM")

    enrich_cves(
        ["CVE-2026-6666"],
        fetcher=fetch,
        cache_dir=tmp_path,
        api_key="secret-key",
        now=NOW,
    )

    by_url = dict(seen)
    assert by_url[KEV_URL] is None
    assert by_url[f"{NVD_URL}?cveId=CVE-2026-6666"] == {"apiKey": "secret-key"}


def test_collect_cve_ids_takes_only_confirmed_values() -> None:
    body = """## Indicators of Compromise
CVE-2026-1111
## Analysis
A reader asked about CVE-2026-9999 in the comments.
"""
    manifest = build_manifest(article_with_cves(body))
    assert "CVE-2026-1111" in collect_cve_ids([manifest])


def test_kev_drives_priority_ordering_and_the_csv(tmp_path) -> None:
    body = """## Indicators of Compromise
CVE-2026-2222
CVE-2026-1111
"""
    manifest = build_manifest(article_with_cves(body))
    intel = {
        "CVE-2026-1111": CveIntel(
            cve_id="CVE-2026-1111",
            kev=True,
            kev_due_date="2026-09-04",
            kev_known_ransomware=True,
            cvss_score=9.8,
            cvss_severity="CRITICAL",
        ),
        "CVE-2026-2222": CveIntel(
            cve_id="CVE-2026-2222", cvss_score=5.3, cvss_severity="MEDIUM"
        ),
    }
    brief = build_brief([manifest], intel=intel)
    patch = [item for item in brief.actions if item.action == "patch"]

    assert patch[0].target == "CVE-2026-1111"
    assert patch[0].priority == "high"
    assert patch[0].kev is True
    assert "KEV 已知遭利用" in patch[0].reason
    assert "CISA 修補期限 2026-09-04" in patch[0].reason
    assert "已用於勒索攻擊" in patch[0].reason
    assert "CVSS 9.8 CRITICAL（NVD）" in patch[0].reason

    assert patch[1].target == "CVE-2026-2222"
    assert patch[1].priority == "medium"
    assert patch[1].kev is False

    assert "KEV" in brief.priority_line
    assert "CVE-2026-1111" in brief.priority_line

    csv_text = render_ioc_csv_from_actions(brief.actions)
    header, first, *_ = csv_text.splitlines()
    assert header.endswith("kev,kev_due_date,cvss_score,cvss_severity")
    assert first.endswith("true,2026-09-04,9.8,CRITICAL")


def test_nvd_cvss_replaces_a_weaker_score_read_from_the_article() -> None:
    body = """## Indicators of Compromise
CVE-2026-1111
CVSS 4.0
"""
    manifest = build_manifest(article_with_cves(body))
    intel = {
        "CVE-2026-1111": CveIntel(
            cve_id="CVE-2026-1111", cvss_score=9.1, cvss_severity="CRITICAL"
        )
    }
    patch = [
        item
        for item in build_brief([manifest], intel=intel).actions
        if item.action == "patch"
    ]

    assert patch[0].priority == "high"
    assert patch[0].cvss_score == 9.1
    assert "（NVD）" in patch[0].reason
