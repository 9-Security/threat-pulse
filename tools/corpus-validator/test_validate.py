#!/usr/bin/env python3
"""Tests for validate.py, runnable on your machine with nothing installed.

    python3 test_validate.py

You told us you could not independently verify our claim that the tests pass,
because the tests were not in the bundle. Fair. These are, they import only the
standard library and `validate.py` beside them, and they build their own tiny
corpus rather than reading the shipped snapshot — so they check the *tool's
behaviour*, independently of whatever data we sent.

Exit code 0 means every assertion held.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import validate  # noqa: E402  - the file under test, beside this one


def _rules() -> dict:
    """Enough public-suffix rules to satisfy the truncation floor, plus real ones.

    The floor exists because a short list answers "not a public suffix" to
    everything, which would put registries back on block lists silently.
    """
    normal = ["com", "net", "org", "uk", "co.uk", "github.io", "duckdns.org"]
    normal += [f"t{n}.invalid" for n in range(1200)]
    return {"normal": sorted(normal), "wildcard": [], "exception": []}


def _snapshot(values=None, excluded=None, cve_intel=None) -> dict:
    snapshot = {
        "schema": "corpus-snapshot/1",
        "generated_at": "2026-09-12T00:00:00+00:00",
        "corpus": {
            "days": 1,
            "first_date": "2026-09-04",
            "last_date": "2026-09-04",
            "confirmed_values": len(values or {}),
            "excluded_values": len(excluded or {}),
            "cve_records": len(cve_intel or {}),
        },
        "public_suffix_list_version": "psl-test",
        "public_suffix_rules": _rules(),
        "coverage": [{"report_date": "2026-09-04", "sources_failed": []}],
        "values": values or {},
        "excluded": excluded or {},
        "cve_intel": cve_intel or {},
        "not_measured_here": ["current-corpus coverage only"],
    }
    snapshot["corpus_version"] = validate.recompute_corpus_version(snapshot)
    return snapshot


def _value(name, kind="domain", citations=None, **extra) -> dict:
    row = {
        "value": name,
        "type": kind,
        "report_dates": ["2026-09-04"],
        "publishers": ["Example Publisher"],
        "citations": citations
        if citations is not None
        else [
            {
                "publisher": "Example Publisher",
                "article_title": "Report",
                "article_url": "https://example.org/report",
                "published_at": "2026-09-04T09:00:00+00:00",
                "report_date": "2026-09-04",
            }
        ],
        "report_count": 1,
        "source_count": 1,
        "first_seen": "2026-09-04",
        "last_seen": "2026-09-04",
    }
    row.update(extra)
    return row


class Run:
    """One run of validate.py as a subprocess, the way you will run it."""

    def __init__(self, snapshot: dict, rows: list):
        self.dir = Path(tempfile.mkdtemp(prefix="validate-test-"))
        self.snapshot_path = self.dir / "snapshot.json"
        self.snapshot_path.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
        (self.dir / "input.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
        self.proc = subprocess.run(
            [
                sys.executable, str(HERE / "validate.py"),
                "--input", str(self.dir / "input.csv"),
                "--snapshot", str(self.snapshot_path),
                "--output", str(self.dir / "results.csv"),
                "--summary", str(self.dir / "summary.json"),
            ],
            capture_output=True, text=True,
        )

    @property
    def rows(self) -> dict:
        import csv

        with (self.dir / "results.csv").open(encoding="utf-8", newline="") as handle:
            return {row["sample_id"]: row for row in csv.DictReader(handle)}

    @property
    def summary(self) -> dict:
        return json.loads((self.dir / "summary.json").read_text(encoding="utf-8"))


class NoNetwork(unittest.TestCase):
    def test_the_source_imports_no_network_module(self):
        """The central claim, checked mechanically rather than by reading."""
        import ast

        tree = ast.parse((HERE / "validate.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

        forbidden = {
            "socket", "ssl", "http", "urllib3", "requests", "httpx", "ftplib",
            "smtplib", "telnetlib", "asyncio", "subprocess", "multiprocessing",
            "ctypes", "importlib",
        }
        self.assertEqual(imported & forbidden, set(), f"unexpected imports: {imported}")
        # urllib.parse is string handling; urllib.request would not be.
        self.assertNotIn("urllib.request", (HERE / "validate.py").read_text(encoding="utf-8"))


class Integrity(unittest.TestCase):
    def test_an_untouched_snapshot_runs(self):
        run = Run(_snapshot({"evil.example.com": _value("evil.example.com")}),
                  ["value,type,sample_id", "evil.example.com,domain,S1"])
        self.assertEqual(run.proc.returncode, 0, run.proc.stderr)
        self.assertEqual(run.rows["S1"]["status"], "hit")

    def test_an_added_value_is_refused(self):
        snapshot = _snapshot({"evil.example.com": _value("evil.example.com")})
        snapshot["values"]["planted.example.com"] = _value("planted.example.com")
        run = Run(snapshot, ["value,type,sample_id", "planted.example.com,domain,S1"])
        self.assertNotEqual(run.proc.returncode, 0)
        self.assertIn("integrity check failed", run.proc.stdout + run.proc.stderr)

    def test_edited_boundary_rules_are_refused(self):
        """The digest must cover the rules, not just the version string.

        Removing a registry from the list makes unrelated tenants match each
        other through it, and nothing else in the output would show that.
        """
        snapshot = _snapshot({"tenant.github.io": _value("tenant.github.io")})
        snapshot["public_suffix_rules"]["normal"] = [
            rule for rule in snapshot["public_suffix_rules"]["normal"] if rule != "github.io"
        ]
        run = Run(snapshot, ["value,type,sample_id", "other.github.io,domain,S1"])
        self.assertNotEqual(run.proc.returncode, 0)
        self.assertIn("integrity check failed", run.proc.stdout + run.proc.stderr)

    def test_a_truncated_value_set_is_refused(self):
        snapshot = _snapshot({"evil.example.com": _value("evil.example.com")})
        snapshot["corpus"]["confirmed_values"] = 99
        run = Run(snapshot, ["value,type,sample_id", "evil.example.com,domain,S1"])
        self.assertNotEqual(run.proc.returncode, 0)


class Matching(unittest.TestCase):
    def setUp(self):
        self.snapshot = _snapshot(
            {
                "evil.example.com": _value("evil.example.com"),
                "tenant.github.io": _value("tenant.github.io"),
                "https://evil.example.com/payload": _value(
                    "https://evil.example.com/payload", kind="url"
                ),
            }
        )

    def test_exact_and_parent_but_never_across_a_registry(self):
        run = Run(self.snapshot, [
            "value,type,sample_id",
            "evil.example.com,domain,S1",
            "api.evil.example.com,domain,S2",
            "other.github.io,domain,S3",
            "deep.tenant.github.io,domain,S4",
        ])
        rows = run.rows
        self.assertEqual(rows["S1"]["match_method"], "exact")
        self.assertEqual(rows["S2"]["match_method"], "parent_domain")
        self.assertEqual(rows["S3"]["status"], "miss")
        self.assertEqual(rows["S4"]["match_method"], "parent_domain")

    def test_a_url_matches_whole_before_host(self):
        run = Run(self.snapshot, [
            "value,type,sample_id",
            "https://evil.example.com/payload,url,S1",
            "https://evil.example.com/other,url,S2",
        ])
        rows = run.rows
        self.assertEqual(rows["S1"]["match_method"], "exact")
        self.assertEqual(rows["S2"]["match_method"], "same_host")

    def test_child_domain_is_outside_the_headline_rate(self):
        run = Run(self.snapshot, ["value,type,sample_id", "example.com,domain,S1"])
        self.assertEqual(run.rows["S1"]["match_method"], "child_domain")
        self.assertEqual(run.summary["by_type"]["domain"]["hit_rate"], 0.0)
        self.assertEqual(run.summary["by_type"]["domain"]["hit_rate_including_child_domain"], 1.0)


class Safety(unittest.TestCase):
    def setUp(self):
        self.snapshot = _snapshot({"evil.example.com": _value("evil.example.com")})

    def test_skipped_is_never_a_miss(self):
        run = Run(self.snapshot, [
            "value,type,sample_id",
            "10.1.2.3,ip,S1",
            "dc01.corp.local,domain,S2",
            "192.168.1.1,domain,S3",
        ])
        rows = run.rows
        self.assertEqual(rows["S1"]["status"], "skipped")
        self.assertEqual(rows["S2"]["status"], "skipped")
        self.assertEqual(rows["S3"]["status"], "skipped", "a wrong label must not defeat the skip")
        self.assertEqual(run.summary["network_combined"]["processed"], 0)

    def test_an_unknown_type_label_is_discarded(self):
        run = Run(self.snapshot, ["value,type,sample_id", "evil.example.com,banana,S1"])
        self.assertEqual(run.rows["S1"]["type_used"], "domain")
        self.assertIn("unknown_supplied_type", run.rows["S1"]["reason"])
        self.assertNotIn("banana", run.summary["by_type"])

    def test_one_bad_row_does_not_end_the_run(self):
        run = Run(self.snapshot, [
            "value,type,sample_id",
            "evil.example.com,domain,S1",
            "http://[::1,url,S2",
            "evil.example.com,domain,S3",
        ])
        rows = run.rows
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows["S2"]["status"], "error")
        self.assertEqual(rows["S3"]["status"], "hit")

    def test_a_hit_that_cannot_be_cited_is_an_error(self):
        snapshot = _snapshot({"uncited.example.com": _value("uncited.example.com", citations=[])})
        run = Run(snapshot, ["value,type,sample_id", "uncited.example.com,domain,S1"])
        self.assertEqual(run.rows["S1"]["status"], "error")
        self.assertIn("missing_citation", run.rows["S1"]["reason"])


class Defanging(unittest.TestCase):
    def setUp(self):
        self.snapshot = _snapshot({"evil.example.com": _value("evil.example.com")})

    def test_mixed_case_and_repeated_passes(self):
        run = Run(self.snapshot, [
            "value,type,sample_id",
            "evil[.]example[.]com,,S1",
            "evil[Dot]example[DOT]com,,S2",
            "hxxp[:]//evil.example.com/a,,S3",
            "hxxps://evil.example.com/b,,S4",
        ])
        rows = run.rows
        for sample in ("S1", "S2"):
            self.assertEqual(rows[sample]["normalized_value"], "evil.example.com")
            self.assertEqual(rows[sample]["status"], "hit")
            self.assertIn("defang", rows[sample]["normalization_applied"])
        self.assertEqual(rows["S3"]["normalized_value"], "evil.example.com")
        self.assertIn("defang_scheme", rows["S3"]["normalization_applied"])
        self.assertEqual(rows["S4"]["status"], "hit")


class Reporting(unittest.TestCase):
    def test_denominators_exclude_what_was_not_looked_up(self):
        snapshot = _snapshot({"evil.example.com": _value("evil.example.com")})
        run = Run(snapshot, [
            "value,type,sample_id",
            "evil.example.com,domain,S1",
            "nothing.example.net,domain,S2",
            "10.1.2.3,ip,S3",
        ])
        domain = run.summary["by_type"]["domain"]
        self.assertEqual(domain["submitted"], 2)
        self.assertEqual(domain["processed"], 2)
        self.assertEqual(domain["hit_rate"], 0.5)
        self.assertEqual(run.summary["by_type"]["ip"]["processed"], 0)

    def test_the_summary_states_what_it_does_not_measure(self):
        snapshot = _snapshot({"evil.example.com": _value("evil.example.com")})
        run = Run(snapshot, ["value,type,sample_id", "evil.example.com,domain,S1"])
        self.assertTrue(run.summary["not_measured_here"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
