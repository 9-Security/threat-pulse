import json

import httpx

from soc_news_parser.sample_export import (
    AnalyzerClient,
    collect_samples,
    high_water_of,
    render_sql,
)

FEED = {
    "/api/feed/recent": [
        {
            "items": [
                {
                    "sha256": "A" * 64,
                    "job_id": "job-1",
                    "sample_id": "s-1",
                    "submitted_at": "2026-09-29T08:00:00+00:00",
                    "finished_at": "2026-09-29T08:04:00+00:00",
                    "file_type": "application/x-dosexec",
                    "size_bytes": 4096,
                },
                {
                    "sha256": "B" * 64,
                    "job_id": "job-2",
                    "sample_id": "s-2",
                    "submitted_at": "2026-09-28T08:00:00+00:00",
                    "finished_at": "2026-09-28T08:04:00+00:00",
                },
            ]
        },
        {"items": []},
    ]
}

IOCS = {
    "job-1": [
        # Defanged in the article style the news side also sees; the shared
        # normaliser has to produce the same value from both.
        {"ioc_type": "domain", "value": "Evil[.]Example[.]COM", "confidence": 84,
         "source_integration_id": "config_extractor", "tags": ["c2"],
         "first_seen_at": "2026-09-29T08:03:00+00:00"},
        # The same domain again from a weaker extraction: the strong row wins.
        {"ioc_type": "domain", "value": "evil.example.com", "confidence": 20,
         "source_integration_id": "strings_entropy", "tags": None,
         "first_seen_at": "2026-09-29T08:03:01+00:00"},
        {"ioc_type": "ip", "value": "45.33.32.156", "confidence": 76,
         "source_integration_id": "config_extractor", "first_seen_at": "2026-09-29T08:03:02+00:00"},
        # Both are refused at query time, so neither is worth holding: a private
        # address, and the documentation range a write-up uses as a stand-in.
        {"ioc_type": "ip", "value": "10.0.0.5", "confidence": 76,
         "source_integration_id": "strings_entropy", "first_seen_at": "2026-09-29T08:03:03+00:00"},
        {"ioc_type": "ip", "value": "203.0.113.9", "confidence": 76,
         "source_integration_id": "strings_entropy", "first_seen_at": "2026-09-29T08:03:07+00:00"},
        # `hash` is split by length so a caller's md5 meets the news side's name.
        {"ioc_type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "confidence": 60,
         "source_integration_id": "ioc_extract", "first_seen_at": "2026-09-29T08:03:04+00:00"},
        # An imphash is a hash to the analyser and not a lookup key here.
        {"ioc_type": "hash", "value": "abc123", "confidence": 10,
         "source_integration_id": "pe_meta", "first_seen_at": "2026-09-29T08:03:05+00:00"},
        {"ioc_type": "mutex", "value": "Global\\\\AgentTeslaMutex", "confidence": 76,
         "source_integration_id": "config_extractor", "first_seen_at": "2026-09-29T08:03:06+00:00"},
    ],
    "job-2": [],
}

SUMMARY = {
    "job-1": {
        "verdict_label": "malicious",
        "verdict_score": 91,
        "family": "AgentTesla",
        "family_confidence": 80,
        "ioc_total": 7,
    },
    "job-2": {"verdict_label": "suspicious", "verdict_score": 40, "ioc_total": 0},
}

SAMPLES = {
    "s-1": {"id": "s-1", "sha256": "A" * 64, "sha1": "1" * 40, "md5": "2" * 32,
            "size_bytes": 4096, "mime": "application/x-dosexec",
            "uploaded_at": "2026-09-29T08:00:00+00:00"},
    "s-2": {"id": "s-2", "sha256": "B" * 64, "sha1": None, "md5": None,
            "size_bytes": 10, "mime": "text/plain",
            "uploaded_at": "2026-09-28T08:00:00+00:00"},
}

ATTACK = {
    "job-1": {"techniques": [{"technique_id": "T1056.001"}, {"technique_id": "T1071.001"}]},
    "job-2": {"techniques": []},
}


def analyzer_client(
    *, fail_summary_for: set[str] = frozenset(), fail_sample_for: set[str] = frozenset()
) -> AnalyzerClient:
    pages = {key: list(value) for key, value in FEED.items()}
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(path)
        if path == "/api/feed/recent":
            offset = int(request.url.params.get("offset", 0))
            queue = pages[path]
            page = queue[0] if offset == 0 else (queue[1] if len(queue) > 1 else {"items": []})
            return httpx.Response(200, json=page)
        if path.startswith("/api/samples/"):
            sample = path.rsplit("/", 1)[-1]
            if sample in fail_sample_for:
                return httpx.Response(500, json={"detail": "boom"})
            return httpx.Response(200, json=SAMPLES.get(sample, {}))
        job = path.split("/")[3]
        if path.endswith("/iocs"):
            return httpx.Response(200, json=IOCS.get(job, []))
        if path.endswith("/threat-intel-summary"):
            if job in fail_summary_for:
                return httpx.Response(500, json={"detail": "boom"})
            return httpx.Response(200, json=SUMMARY.get(job, {}))
        if path.endswith("/attack-summary"):
            return httpx.Response(200, json=ATTACK.get(job, {"techniques": []}))
        return httpx.Response(404, json={"detail": "not found"})

    client = AnalyzerClient(
        "http://analyzer.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )
    client.calls = calls  # type: ignore[attr-defined]
    return client


def test_indicators_are_normalised_the_way_the_news_side_normalises_them() -> None:
    """A lookup that hits on one side and misses on the other is the failure to avoid."""
    with analyzer_client() as analyzer:
        samples = collect_samples(analyzer)

    first = next(s for s in samples if s.sha256.startswith("a"))
    values = {(i.indicator_type, i.value): i for i in first.indicators}
    assert ("domain", "evil.example.com") in values, "defanged and plain forms must fold together"
    assert values[("domain", "evil.example.com")].confidence == 84, "the stronger claim wins"
    assert values[("domain", "evil.example.com")].integration == "config_extractor"
    assert values[("domain", "evil.example.com")].registrable_lc == "example.com"
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in values, "`hash` is split by length"
    assert ("ip", "45.33.32.156") in values
    assert ("ip", "10.0.0.5") not in values, "a private address is refused at query time"
    assert ("ip", "203.0.113.9") not in values, "so is the documentation range"
    assert not any(t == "hash" for t, _ in values), "no value stays under the generic name"
    assert not any(v == "abc123" for _, v in values), "an imphash is not a lookup key"
    assert ("mutex", "Global\\\\AgentTeslaMutex") in values


def test_the_summary_travels_with_the_sample() -> None:
    with analyzer_client() as analyzer:
        samples = collect_samples(analyzer)

    first = next(s for s in samples if s.sha256.startswith("a"))
    assert (first.verdict, first.verdict_score) == ("malicious", 91)
    assert (first.family, first.family_confidence) == ("AgentTesla", 80)
    assert first.attack_techniques == ("T1056.001", "T1071.001")
    assert first.report_url == f"https://malware.nine-security.com/s/{'a' * 64}"


def test_a_caller_can_arrive_by_md5_or_sha1() -> None:
    """The one lookup the news side can never answer, so it has to work here."""
    with analyzer_client() as analyzer:
        samples = collect_samples(analyzer)

    first = next(s for s in samples if s.sha256.startswith("a"))
    assert first.md5 == "2" * 32
    assert first.sha1 == "1" * 40
    sql = render_sql(samples)
    assert "'" + "2" * 32 + "'" in sql

    with analyzer_client(fail_sample_for={"s-1"}) as analyzer:
        degraded = collect_samples(analyzer)
        failures = list(analyzer.failures)
    still = next(s for s in degraded if s.sha256.startswith("a"))
    assert still.indicators and still.md5 is None, "one endpoint failing loses that field only"
    assert any("sample" in note for note in failures)


def test_a_failed_summary_still_exports_the_values() -> None:
    """The values are what a lookup needs; losing them over one endpoint is worse."""
    with analyzer_client(fail_summary_for={"job-1"}) as analyzer:
        samples = collect_samples(analyzer)
        failures = list(analyzer.failures)

    first = next(s for s in samples if s.sha256.startswith("a"))
    assert first.indicators, "indicators survive a failed summary"
    assert first.family is None and first.verdict_score is None
    assert any("summary" in note for note in failures), "and the failure is reported"


def test_the_high_water_mark_stops_a_run_at_what_it_already_has() -> None:
    with analyzer_client() as analyzer:
        samples = collect_samples(analyzer, stop_at="2026-09-28T08:04:00+00:00")

    assert [s.sha256[:1] for s in samples] == ["a"], "the older sample is already exported"
    assert high_water_of(samples) == "2026-09-29T08:04:00+00:00"
    assert high_water_of([], "2026-09-29T08:04:00+00:00") == "2026-09-29T08:04:00+00:00"


def test_a_first_pass_can_be_capped() -> None:
    with analyzer_client() as analyzer:
        assert len(collect_samples(analyzer, max_samples=1)) == 1


def test_the_sql_is_upserts_and_carries_the_freshness_in_the_same_batch() -> None:
    with analyzer_client() as analyzer:
        samples = collect_samples(analyzer)

    sql = render_sql(samples, exported_at="2026-09-30T02:00:00+00:00", high_water="2026-09-29T08:04:00+00:00")
    assert "INSERT OR REPLACE INTO sample_analysis" in sql
    assert "INSERT OR REPLACE INTO sample_indicators" in sql
    assert "INSERT OR REPLACE INTO sample_state" in sql
    assert "DELETE" not in sql, "a re-run must not empty a table it then fails to fill"
    assert sql.index("sample_state") > sql.index("sample_indicators"), "freshness is written last"
    assert "'2026-09-29T08:04:00+00:00'" in sql
    assert json.dumps(["T1056.001", "T1071.001"]).replace('"', '"') in sql or "T1056.001" in sql
    assert "10.0.0.5" not in sql


def test_a_quote_in_a_value_cannot_break_the_batch() -> None:
    from soc_news_parser.sample_export import SampleAnalysis, SampleIndicator

    nasty = SampleIndicator(
        sha256="c" * 64,
        indicator_type="path",
        value="C:\\Users\\O'Brien\\run.exe",
        confidence=50,
        integration="strings_entropy",
        tags=(),
        first_seen_at="2026-09-29T08:00:00+00:00",
        registrable_lc=None,
    )
    sample = SampleAnalysis(
        sha256="c" * 64, md5=None, sha1=None, size_bytes=None, file_type=None,
        submitted_at=None, finished_at=None, verdict=None, verdict_score=None,
        family=None, family_confidence=None, attack_techniques=(), ioc_total=None,
        indicators=(nasty,),
    )
    assert "O''Brien" in render_sql([sample])
