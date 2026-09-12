import csv
import json
import subprocess
import sys
from pathlib import Path

from soc_news_parser.snapshot import build_snapshot, write_bundle

VALIDATOR = Path(__file__).resolve().parents[1] / "tools" / "corpus-validator" / "validate.py"


def _day(root: Path, date: str, evidence: list[dict], actions: list[dict] | None = None,
         cve_intel: dict | None = None, failures: list[str] | None = None) -> None:
    folder = root / date
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "daily-evidence.json").write_text(
        json.dumps(
            {
                "window_start": f"{date}T00:00:00+00:00",
                "window_end": f"{date}T22:00:00+00:00",
                "article_count": 1,
                "sources_checked": ["the-hacker-news", "cisa-advisories"],
                "source_failures": [
                    {"source_key": key, "source_name": key, "error": "403"} for key in failures or []
                ],
                "articles": [
                    {
                        "source": "The Hacker News",
                        "article_title": f"Report for {date}",
                        "article_url": f"https://thehackernews.com/{date}",
                        "published_at": f"{date}T09:00:00+00:00",
                        "canonical_body": "x" * 5000,
                        "evidence": evidence,
                    }
                ],
                "analyst_brief": {"actions": actions or []},
                "cve_intel": cve_intel or {},
            }
        ),
        encoding="utf-8",
    )


def _corpus(tmp_path: Path) -> Path:
    root = tmp_path / "reports"
    _day(
        root,
        "2026-09-04",
        [
            {"indicator_type": "domain", "normalized_value": "evil.example.com", "status": "confirmed"},
            {"indicator_type": "cve", "normalized_value": "CVE-2026-1111", "status": "confirmed"},
            {
                "indicator_type": "domain",
                "normalized_value": "thehackernews.com",
                "status": "rejected",
                "reason_codes": ["publisher_domain"],
            },
        ],
        actions=[{"target_type": "domain", "target": "evil.example.com", "action": "block",
                  "priority": "high"}],
        cve_intel={
            "CVE-2026-1111": {
                "cve_id": "CVE-2026-1111", "kev": True, "cvss_score": 9.8,
                "epss_score": 0.42, "sources": ["https://nvd.example/CVE-2026-1111"],
            }
        },
        failures=["cisa-advisories"],
    )
    return root


def test_article_bodies_never_travel(tmp_path: Path) -> None:
    """26 publishers' text, several under redistribution terms, and no match needs it."""
    snapshot = build_snapshot(_corpus(tmp_path))

    assert "x" * 5000 not in json.dumps(snapshot)


def test_excluded_values_travel_with_their_reasons(tmp_path: Path) -> None:
    """"Ruled out" and "never seen" are different answers; only this carries the first."""
    snapshot = build_snapshot(_corpus(tmp_path))

    assert snapshot["excluded"]["thehackernews.com"]["reason_codes"] == ["publisher_domain"]


def test_source_failures_travel_so_a_gap_is_visible(tmp_path: Path) -> None:
    """A value absent because its publisher was unreachable is not a value nobody reported."""
    snapshot = build_snapshot(_corpus(tmp_path))

    assert snapshot["coverage"][0]["sources_failed"] == ["cisa-advisories"]


def test_corpus_version_ignores_build_time(tmp_path: Path) -> None:
    """The same corpus must reproduce the same result, so rebuilding is not a change."""
    root = _corpus(tmp_path)

    first = build_snapshot(root)
    second = build_snapshot(root)

    assert first["generated_at"] is not None
    assert first["corpus_version"] == second["corpus_version"]


def test_corpus_version_moves_when_a_value_is_added(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    before = build_snapshot(root)["corpus_version"]
    _day(root, "2026-09-05",
         [{"indicator_type": "ip", "normalized_value": "104.21.5.10", "status": "confirmed"}])

    assert build_snapshot(root)["corpus_version"] != before


def test_counts_are_reports_and_publishers(tmp_path: Path) -> None:
    """report_count counts days; source_count counts distinct publishers."""
    root = _corpus(tmp_path)
    _day(root, "2026-09-05",
         [{"indicator_type": "domain", "normalized_value": "evil.example.com", "status": "confirmed"}])
    snapshot = build_snapshot(root)

    row = snapshot["values"]["evil.example.com"]
    assert row["report_count"] == 2
    assert row["source_count"] == 1  # the same publisher on both days
    assert row["first_seen"] == "2026-09-04"
    assert row["last_seen"] == "2026-09-05"


def _run_validator(bundle: Path, rows: list[str]) -> tuple[list[dict], dict]:
    (bundle / "input.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(bundle / "validate.py"),
         "--input", str(bundle / "input.csv"),
         "--snapshot", str(bundle / "corpus-snapshot.json"),
         "--output", str(bundle / "results.csv"),
         "--summary", str(bundle / "summary.json")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    with (bundle / "results.csv").open(encoding="utf-8", newline="") as handle:
        results = list(csv.DictReader(handle))
    return results, json.loads((bundle / "summary.json").read_text(encoding="utf-8"))


def test_the_shipped_validator_runs_as_the_consumer_will_run_it(tmp_path: Path) -> None:
    """Runs the actual file that is handed over, as a subprocess, on the stock interpreter.

    Testing the functions by import would prove the logic and not the artefact.
    What is handed over is one file that has to start and run on a machine with
    no project environment, which is a different claim.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))
    assert (bundle / "validate.py").is_file()
    assert (bundle / "README.md").is_file()

    results, summary = _run_validator(
        bundle,
        [
            "value,type,sample_id",
            "evil.example.com,domain,S1",
            "api.evil.example.com,domain,S2",   # parent_domain
            "CVE-2026-1111,cve,S3",
            "thehackernews.com,domain,S4",      # excluded
            "10.1.2.3,ip,S5",                   # skipped
            "dc01.corp.local,domain,S6",        # skipped
            "nothing-here.example.net,domain,S7",
        ],
    )

    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["status"] == "hit" and by_id["S1"]["match_method"] == "exact"
    assert by_id["S2"]["match_method"] == "parent_domain"
    assert by_id["S2"]["matched_value"] == "evil.example.com"
    assert by_id["S3"]["kev"] == "True" and by_id["S3"]["cvss_score"] == "9.8"
    assert by_id["S3"]["cve_provenance"] == "https://nvd.example/CVE-2026-1111"
    assert by_id["S4"]["status"] == "excluded"
    assert by_id["S5"]["status"] == "skipped" and by_id["S5"]["reason"] == "non_public_ip"
    assert by_id["S6"]["status"] == "skipped" and by_id["S6"]["reason"] == "internal_hostname"
    assert by_id["S7"]["status"] == "miss"

    # Every hit carries the citation that supports it.
    assert by_id["S1"]["citation_url"] == "https://thehackernews.com/2026-09-04"
    assert by_id["S1"]["citation_publisher"] == "The Hacker News"
    assert by_id["S1"]["publication_date"] == "2026-09-04T09:00:00+00:00"

    # Denominators exclude what was never looked up.
    assert summary["by_type"]["domain"]["submitted"] == 5
    assert summary["by_type"]["domain"]["processed"] == 4  # dc01.corp.local skipped
    assert summary["by_type"]["domain"]["skipped"] == 1
    assert summary["by_type"]["ip"]["processed"] == 0  # the private address never counts
    assert summary["by_type"]["cve"]["hit_rate"] == 1.0
    # CVEs are never folded into the network rate.
    assert summary["network_combined"]["processed"] == 4


def test_a_parent_match_never_crosses_a_registry(tmp_path: Path) -> None:
    """`github.io` is a registry; matching there would tie unrelated tenants together."""
    root = _corpus(tmp_path)
    _day(root, "2026-09-05",
         [{"indicator_type": "domain", "normalized_value": "tenant.github.io", "status": "confirmed"}])
    bundle = tmp_path / "bundle"
    write_bundle(bundle, root)

    results, _ = _run_validator(
        bundle,
        ["value,type,sample_id",
         "someone-else.github.io,domain,S1",
         "deep.tenant.github.io,domain,S2"],
    )

    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["status"] == "miss"
    assert by_id["S2"]["match_method"] == "parent_domain"
    assert by_id["S2"]["matched_value"] == "tenant.github.io"


def test_child_domain_is_reported_but_kept_out_of_the_headline_rate(tmp_path: Path) -> None:
    """Their thresholds were written for three relations; widening them silently
    would move the number against a rule set for something narrower."""
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    results, summary = _run_validator(
        bundle, ["value,type,sample_id", "example.com,domain,S1"]
    )

    assert results[0]["match_method"] == "child_domain"
    assert results[0]["matched_value"] == "evil.example.com"
    assert summary["by_type"]["domain"]["hit_rate"] == 0.0
    assert summary["by_type"]["domain"]["hit_rate_including_child_domain"] == 1.0


def test_the_summary_states_what_it_does_not_measure(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    _, summary = _run_validator(bundle, ["value,type,sample_id", "evil.example.com,domain,S1"])

    joined = " ".join(summary["not_measured_here"])
    assert "at the time of each alert" in joined
    assert "not detection performance" in joined


def test_every_publisher_is_listed_not_just_the_first(tmp_path: Path) -> None:
    """`source_count` cannot tell corroboration from republication.

    In the real corpus every network indicator with more than one publisher is
    an aggregator carrying an original researcher's report. A reader needs the
    names to see that, so a count alone would overstate what was independent.
    """
    root = _corpus(tmp_path)
    folder = root / "2026-09-05"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "daily-evidence.json").write_text(
        json.dumps(
            {
                "articles": [
                    {
                        "source": "Cyber Security News",
                        "article_title": "Republished",
                        "article_url": "https://cybersecuritynews.example/1",
                        "published_at": "2026-09-05T09:00:00+00:00",
                        "evidence": [
                            {"indicator_type": "domain", "normalized_value": "evil.example.com",
                             "status": "confirmed"}
                        ],
                    }
                ],
                "analyst_brief": {"actions": []},
            }
        ),
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    write_bundle(bundle, root)

    results, _ = _run_validator(bundle, ["value,type,sample_id", "evil.example.com,domain,S1"])

    assert results[0]["source_count"] == "2"
    assert results[0]["publishers"] == "The Hacker News; Cyber Security News"
