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


def test_defanged_input_is_undefanged_and_the_change_is_named(tmp_path: Path) -> None:
    """The documents promised this and the code did not do it.

    `docs/data-handling.md` and the specification both state that defanged input
    is accepted. A value exported from a ticket as `evil[.]com` was classified
    `unsupported_type` and dropped from the denominator instead -- a documented
    promise the code did not keep, which the reviewers found by reading both.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    results, summary = _run_validator(
        bundle,
        ["value,type,sample_id",
         "evil[.]example[.]com,,S1",
         "hxxps://evil.example.com/path,,S2"],
    )

    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["status"] == "hit"
    assert by_id["S1"]["normalized_value"] == "evil.example.com"
    assert "defang" in by_id["S1"]["normalization_applied"]
    assert by_id["S2"]["status"] == "hit"
    assert "defang_scheme" in by_id["S2"]["normalization_applied"]
    # And it must not be quietly counted as unsupported any more.
    assert "unknown" not in summary["by_type"]


def test_a_wrong_type_label_cannot_defeat_a_safety_skip(tmp_path: Path) -> None:
    """A private address declared as `domain` was looked up and reported `miss`.

    That put it in the denominator and answered "not found" for a value that was
    never eligible -- the exact thing the review's hard requirement forbids. Skip
    checks now run against the supplied type and the detected one, and a skip
    from either wins.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    results, summary = _run_validator(
        bundle,
        ["value,type,sample_id",
         "10.1.2.3,domain,S1",
         "dc01.corp.local,ip,S2"],
    )

    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["status"] == "skipped"
    assert "non_public_ip" in by_id["S1"]["reason"]
    assert "type_mismatch" in by_id["S1"]["reason"]
    assert by_id["S2"]["status"] == "skipped"
    # Neither reaches a denominator.
    assert summary["network_combined"]["processed"] == 0


def test_one_bad_row_produces_an_error_row_not_a_dead_run(tmp_path: Path) -> None:
    """`status=error` was documented and unreachable.

    There was no per-row guard, so a value that raised took the whole run with
    it: the promise was a row per input, and the behaviour was a traceback and
    no output at all.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    results, _ = _run_validator(
        bundle,
        ["value,type,sample_id",
         "evil.example.com,domain,S1",
         "http://[::1,url,S2",
         "CVE-2026-1111,cve,S3"],
    )

    assert len(results) == 3
    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["status"] == "hit"
    assert by_id["S3"]["status"] == "hit"
    assert by_id["S2"]["status"] == "error"
    assert "ValueError" in by_id["S2"]["reason"]


def test_a_value_that_cannot_be_cited_is_not_a_hit(tmp_path: Path) -> None:
    """The specification requires it; only the data made it true by accident.

    A hit with a blank citation column satisfies "one row per value" and breaks
    the rule the row exists to enforce, so the check belongs in the code rather
    than in an invariant nobody asserts.
    """
    root = tmp_path / "reports"
    folder = root / "2026-09-04"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "daily-evidence.json").write_text(
        json.dumps(
            {
                "articles": [
                    {
                        "source": "The Hacker News",
                        "article_title": "No link on this item",
                        "article_url": None,
                        "published_at": "2026-09-04T09:00:00+00:00",
                        "evidence": [
                            {"indicator_type": "domain", "normalized_value": "uncited.example.com",
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

    results, _ = _run_validator(bundle, ["value,type,sample_id", "uncited.example.com,domain,S1"])

    assert results[0]["status"] == "error"
    assert "missing_citation" in results[0]["reason"]
    assert results[0]["citation_url"] == ""


def test_a_full_url_matches_whole_before_it_is_reduced_to_a_host(tmp_path: Path) -> None:
    """Corpus URLs were unreachable and host matches were labelled `same_host`.

    The stronger relation existed in the data and could never be reported,
    because the submitted URL was reduced to its host before anything was tried.
    """
    root = _corpus(tmp_path)
    folder = root / "2026-09-05"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "daily-evidence.json").write_text(
        json.dumps(
            {
                "articles": [
                    {
                        "source": "The Hacker News",
                        "article_title": "With a URL indicator",
                        "article_url": "https://thehackernews.com/2026-09-05",
                        "published_at": "2026-09-05T09:00:00+00:00",
                        "evidence": [
                            {"indicator_type": "url",
                             "normalized_value": "https://evil.example.com/payload",
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

    results, _ = _run_validator(
        bundle,
        ["value,type,sample_id",
         "https://evil.example.com/payload,url,S1",
         "https://evil.example.com/other,url,S2"],
    )

    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["match_method"] == "exact"
    assert by_id["S1"]["matched_value"] == "https://evil.example.com/payload"
    # A different path still finds the host, and is labelled as the weaker match.
    assert by_id["S2"]["match_method"] == "same_host"
    assert by_id["S2"]["matched_value"] == "evil.example.com"


def test_an_altered_snapshot_is_refused_rather_than_trusted(tmp_path: Path) -> None:
    """corpus_version was read and believed.

    A truncated or edited snapshot then reports the version it claims rather
    than the version it is, and every result carries that claim into the
    consumer's records.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))
    path = bundle / "corpus-snapshot.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["values"]["planted.example.com"] = {
        "value": "planted.example.com", "type": "domain", "report_dates": ["2026-09-04"],
        "publishers": ["The Hacker News"], "citations": [], "report_count": 1,
        "source_count": 1, "first_seen": "2026-09-04", "last_seen": "2026-09-04",
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    (bundle / "input.csv").write_text("value,type,sample_id\nplanted.example.com,domain,S1\n",
                                      encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(bundle / "validate.py"),
         "--input", str(bundle / "input.csv"),
         "--snapshot", str(path),
         "--output", str(bundle / "r.csv"),
         "--summary", str(bundle / "s.json")],
        capture_output=True, text=True,
    )

    assert result.returncode != 0
    assert "integrity check failed" in (result.stdout + result.stderr)
    assert not (bundle / "r.csv").exists()


def test_an_untouched_snapshot_verifies(tmp_path: Path) -> None:
    """The guard has to pass on the real artefact, or it is just a blocker."""
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    _, summary = _run_validator(bundle, ["value,type,sample_id", "evil.example.com,domain,S1"])

    assert summary["corpus_version"] == summary["corpus_version_recomputed"]


def test_editing_the_boundary_rules_is_caught(tmp_path: Path) -> None:
    """The digest covered the PSL *version string*, not the rules.

    That left the one part of the bundle which decides where a parent match
    stops editable without detection. Remove `github.io` from the normal set,
    keep the version string, and every tenant beneath it starts matching every
    other tenant -- with the integrity check still passing and the results
    looking ordinary.
    """
    root = _corpus(tmp_path)
    _day(root, "2026-09-05",
         [{"indicator_type": "domain", "normalized_value": "tenant.github.io", "status": "confirmed"}])
    bundle = tmp_path / "bundle"
    write_bundle(bundle, root)
    path = bundle / "corpus-snapshot.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    rules = payload["public_suffix_rules"]["normal"]
    assert "github.io" in rules, "fixture assumption: the registry is in the list"
    payload["public_suffix_rules"]["normal"] = [r for r in rules if r != "github.io"]
    # The version string is left untouched, which is the whole point.
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    (bundle / "input.csv").write_text(
        "value,type,sample_id\nsomeone-else.github.io,domain,S1\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(bundle / "validate.py"),
         "--input", str(bundle / "input.csv"), "--snapshot", str(path),
         "--output", str(bundle / "r.csv"), "--summary", str(bundle / "s.json")],
        capture_output=True, text=True,
    )

    assert result.returncode != 0
    assert "integrity check failed" in (result.stdout + result.stderr)
    assert not (bundle / "r.csv").exists()


def test_an_unknown_supplied_type_is_reported_and_discarded(tmp_path: Path) -> None:
    """A typo used to become a statistics bucket.

    `banana` was carried straight through into `type_used`, creating its own row
    in the per-type rates and reaching the lookup with whatever normalisation
    the fallback happened to apply.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    results, summary = _run_validator(
        bundle,
        ["value,type,sample_id",
         "evil.example.com,banana,S1",
         "10.1.2.3,banana,S2"],
    )

    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["type_used"] == "domain"  # detection, not the label
    assert "unknown_supplied_type:banana" in by_id["S1"]["reason"]
    assert by_id["S1"]["status"] == "hit"
    # And the bad label cannot smuggle a private address past the skip either.
    assert by_id["S2"]["status"] == "skipped"
    assert "banana" not in summary["by_type"]


def test_defanging_is_case_insensitive_and_settles(tmp_path: Path) -> None:
    """`[Dot]` is as common in a ticket as `[dot]`, and `hxxp[:]//` needs two passes.

    The first implementation matched only all-lower and all-upper forms, and ran
    scheme restoration before punctuation restoration -- so a value that needed
    both was left half-converted and classified unsupported.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))

    results, _ = _run_validator(
        bundle,
        ["value,type,sample_id",
         "evil[Dot]example[DOT]com,,S1",
         "hxxp[:]//evil.example.com/a,,S2",
         "EVIL[.]example[.]COM,,S3"],
    )

    by_id = {row["sample_id"]: row for row in results}
    assert by_id["S1"]["normalized_value"] == "evil.example.com"
    assert by_id["S1"]["status"] == "hit"
    assert by_id["S2"]["type_detected"] == "url"
    assert by_id["S2"]["normalized_value"] == "evil.example.com"
    assert "defang_scheme" in by_id["S2"]["normalization_applied"]
    assert by_id["S3"]["status"] == "hit"


def test_the_bundle_ships_its_own_test_file(tmp_path: Path) -> None:
    """They said they could not independently verify the claim that tests pass.

    So the tests travel with the tool, and run without the project: a claim the
    consumer cannot check is a claim they are right to discount.
    """
    bundle = tmp_path / "bundle"
    write_bundle(bundle, _corpus(tmp_path))
    shipped = bundle / "test_validate.py"
    assert shipped.is_file()

    result = subprocess.run(
        [sys.executable, str(shipped)], capture_output=True, text=True, cwd=str(bundle)
    )

    assert result.returncode == 0, result.stdout + result.stderr
