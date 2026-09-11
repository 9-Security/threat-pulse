import json
from pathlib import Path

from soc_news_parser.backtest import (
    load_corpus,
    match_cves,
    match_observables,
    read_values,
    run_backtest,
)


def _write_day(root: Path, date: str, evidence: list[dict], actions: list[dict]) -> None:
    folder = root / date
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "daily-evidence.json").write_text(
        json.dumps(
            {
                "articles": [
                    {
                        "source": "The Hacker News",
                        "article_title": f"Report for {date}",
                        "article_url": f"https://thehackernews.com/{date}",
                        "evidence": evidence,
                    }
                ],
                "analyst_brief": {"actions": actions},
            }
        ),
        encoding="utf-8",
    )


def _corpus(tmp_path: Path) -> Path:
    root = tmp_path / "reports"
    _write_day(
        root,
        "2026-09-04",
        [
            {"indicator_type": "domain", "normalized_value": "evil.example.com", "status": "confirmed"},
            {"indicator_type": "ip", "normalized_value": "104.21.5.10", "status": "confirmed"},
            {"indicator_type": "domain", "normalized_value": "8.8.8.8", "status": "confirmed"},
            {"indicator_type": "cve", "normalized_value": "CVE-2026-1111", "status": "confirmed"},
            {
                "indicator_type": "domain",
                "normalized_value": "thehackernews.com",
                "status": "rejected",
                "reason_codes": ["publisher_domain"],
            },
        ],
        [
            {"target_type": "domain", "target": "evil.example.com", "action": "block",
             "reason": "block it"},
            {"target_type": "domain", "target": "8.8.8.8", "action": "hunt",
             "benign_basis": "public_resolver_registry", "reason": "public resolver"},
            {"target_type": "cve", "target": "CVE-2026-1111", "action": "patch",
             "kev": True, "cvss_score": 9.8, "epss_score": 0.42, "priority": "high"},
        ],
    )
    return root


def test_skipped_values_are_never_reported_as_unseen(tmp_path: Path) -> None:
    """"We did not look" and "we looked and found nothing" are different answers.

    A private address or an internal hostname cannot appear in a corpus of
    published reporting, and sending one there leaks internal structure. The
    reviewers asked for these to be skipped rather than answered.
    """
    corpus = load_corpus(_corpus(tmp_path))
    result = match_observables(
        ["10.1.2.3", "dc01.corp.local", "104.21.5.10", "nothing-here.example.org"],
        corpus,
    )

    assert result["skipped"] == 2
    assert {item["reason_code"] for item in result["detail"]["skipped"]} == {
        "non_public_ip",
        "internal_hostname",
    }
    assert result["unseen"] == 1
    assert "10.1.2.3" not in result["detail"]["unseen"]
    # The hit rate is over what was actually processed, not what was submitted.
    assert result["processed"] == 2
    assert result["hit_rate"] == 0.5


def test_a_subdomain_matches_its_parent_but_not_across_a_registry(tmp_path: Path) -> None:
    """Parent matching stops where the Worker's does.

    A log names the host that resolved, which is often a child of the host a
    report named. It must not walk past the registrable domain: `github.io` is a
    registry, and matching there would tie every unrelated tenant together.
    """
    root = _corpus(tmp_path)
    _write_day(
        root,
        "2026-09-05",
        [{"indicator_type": "domain", "normalized_value": "tenant.github.io", "status": "confirmed"}],
        [{"target_type": "domain", "target": "tenant.github.io", "action": "block"}],
    )
    corpus = load_corpus(root)

    matched = match_observables(["api.evil.example.com"], corpus)
    assert matched["by_match"] == {"parent_domain": 1}
    assert matched["detail"]["hits"][0]["matched_on"] == "evil.example.com"

    # A different tenant under the same registry is not a match.
    other = match_observables(["someone-else.github.io"], corpus)
    assert other["hits"] == 0
    assert other["unseen"] == 1


def test_excluded_values_are_reported_separately_from_unseen(tmp_path: Path) -> None:
    """The one measurement D1 cannot produce.

    Rejected rows never leave the audit archive, so a backtest reading D1 would
    report a publisher's own domain as "unseen" -- losing the distinction the
    reviewers said was the excluded bucket's whole value.
    """
    corpus = load_corpus(_corpus(tmp_path))
    result = match_observables(["thehackernews.com", "unrelated.example.net"], corpus)

    assert result["excluded"] == 1
    assert result["unseen"] == 1
    assert result["detail"]["excluded"][0]["reason_codes"] == ["publisher_domain"]


def test_benign_listed_hits_are_counted_as_their_own_outcome(tmp_path: Path) -> None:
    corpus = load_corpus(_corpus(tmp_path))
    result = match_observables(["8.8.8.8"], corpus)

    assert result["hits"] == 1
    assert result["benign_listed"] == 1
    assert result["detail"]["hits"][0]["benign_basis"] == "public_resolver_registry"


def test_cve_hits_carry_the_signals_that_rank_them(tmp_path: Path) -> None:
    corpus = load_corpus(_corpus(tmp_path))
    result = match_cves(["CVE-2026-1111", "CVE-2026-9999", "not-a-cve"], corpus)

    assert result["malformed"] == 1
    assert result["hits"] == 1
    assert result["hit_rate"] == 0.5  # over the two well-formed ids
    assert result["kev"] == 1
    assert result["with_cvss"] == 1
    assert result["with_epss"] == 1
    assert result["with_any_ranking_signal"] == 1


def test_the_result_says_what_it_did_not_measure(tmp_path: Path) -> None:
    """The acceptance measure that matters most is not computable here.

    Decision-change rate needs a human reading the hits against the original
    alerts. Reporting a hit rate without saying so would invite it to be read as
    the verdict.
    """
    result = run_backtest(observables=["8.8.8.8"], cves=None, reports_dir=_corpus(tmp_path))

    assert result["corpus"]["days"] == 1
    joined = " ".join(result["not_measured_here"])
    assert "decision-change" in joined
    assert "latency" in joined


def test_read_values_accepts_a_csv_export(tmp_path: Path) -> None:
    path = tmp_path / "values.csv"
    path.write_text(
        '﻿"value","first_seen"\n# a comment\n\n"evil.example.com",2026-09-04\n8.8.8.8,x\n',
        encoding="utf-8",
    )
    # The BOM this project writes on its own CSVs must not become part of a value.
    assert read_values(path) == ["value", "evil.example.com", "8.8.8.8"]
