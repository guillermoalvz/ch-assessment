"""Offline checks for scanner failure handling, counts, and report safety."""

import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import audit_dependencies as audit


class AuditReportingTests(unittest.TestCase):
    def test_advisory_repeated_on_multiple_paths_counts_once(self):
        rows = [audit.finding("snyk", "example", "SNYK-1", "Pollution", "high",
                              versions=["1.0.0"], paths=[path], fix_available=fix)
                for path, fix in (("app > example", True), ("app > parent > example", False))]
        findings = audit.aggregate(rows)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0]["paths"]), 2)
        self.assertTrue(findings[0]["fix_available"])

    def test_npm_inherited_package_is_not_an_extra_advisory(self):
        data = {"metadata": {"vulnerabilities": {"total": 2}}, "vulnerabilities": {
            "parent": {"via": ["child"], "fixAvailable": True},
            "child": {"via": [{"source": 1, "title": "Pollution", "severity": "high",
                                "url": "https://github.com/advisories/GHSA-example"}],
                      "fixAvailable": True}}}
        rows, _ = audit.parse_npm(data, {})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["package"], "child")

    def test_partial_and_error_scans_are_rejected(self):
        for parser, data in ((audit.parse_yarn, '{"type":"info","data":"started"}\n'),
                             (audit.parse_yarn, '{"type":"error","data":"network failure"}\n'),
                             (audit.parse_snyk, {"ok": False, "error": "Authentication failed"}),
                             (audit.parse_snyk, {})):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parser(data)
        with self.assertRaises(ValueError):
            audit.parse_npm({"error": {"code": "EAUDITNOLOCK"}}, {})

    def test_snyk_medium_is_normalized_without_losing_fix(self):
        rows, _ = audit.parse_snyk({"ok": False, "uniqueCount": 1, "vulnerabilities": [
            {"id": "SNYK-1", "name": "example", "title": "Issue", "severity": "medium",
             "version": "1.0.0", "from": ["app", "example"], "fixedIn": ["1.0.1"],
             "isUpgradable": False}]})
        self.assertEqual(rows[0]["severity"], "medium")
        self.assertEqual(rows[0]["fixed_versions"], ["1.0.1"])
        self.assertFalse(rows[0]["fix_available"])

    def test_completed_clean_scans_and_execution_errors_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"name":"test"}')
            raw = root / "reports" / "raw"
            raw.mkdir(parents=True)
            (raw / audit.RAW_NAMES["npm"]).write_text(json.dumps(
                {"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}))
            (raw / audit.RAW_NAMES["yarn"]).write_text(json.dumps(
                {"type": "auditSummary", "data": {"vulnerabilities": {"high": 0}}}) + "\n")
            (raw / audit.RAW_NAMES["snyk"]).write_text('{"ok":true,"vulnerabilities":[]}')
            metadata = {scanner: {"exit_code": 0} for scanner in audit.COMMANDS}
            report = audit.build_report(root, raw.parent, metadata)
            self.assertEqual(report["findings"], [])
            self.assertTrue(all(s["status"] == "completed" for s in report["scans"].values()))
            metadata["snyk"] = {"execution_error": "Timed out", "exit_code": None}
            report = audit.build_report(root, raw.parent, metadata)
            self.assertEqual(report["scans"]["snyk"]["status"], "error")
            metadata["snyk"] = {"exit_code": 2}
            report = audit.build_report(root, raw.parent, metadata)
            self.assertEqual(report["scans"]["snyk"]["status"], "error")

    def test_csv_neutralizes_spreadsheet_formulas_and_preserves_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = audit.finding("npm", "example", "1", '=HYPERLINK("bad")', "high")
            audit.save_report({"findings": [row]}, root)
            with (root / "vulnerabilities.csv").open() as handle:
                csv_row = next(csv.DictReader(handle))
            self.assertTrue(csv_row["title"].startswith("'="))
            saved = json.loads((root / "vulnerabilities.json").read_text())
            self.assertEqual(saved["findings"][0]["title"], row["title"])
            with (root / "vulnerabilities-dedup.csv").open() as handle:
                dedup_row = next(csv.DictReader(handle))
            self.assertTrue(dedup_row["titles"].startswith("'="))

    def test_shared_ghsa_and_cve_bridge_merge_across_scanners(self):
        rows = [
            audit.finding("npm", "library", "GHSA-abcd-1234-5678", "Issue", "critical",
                          versions=["1.0"], paths=["node_modules/library"], fix_available=True),
            audit.finding("yarn", "library", "GHSA-abcd-1234-5678", "Issue", "moderate",
                          cves=["CVE-2026-12345"], versions=["1.0"], fixed_versions=[">=2.0"]),
            audit.finding("snyk", "library", "SNYK-123", "Different title", "high",
                          cves=["CVE-2026-12345"], paths=["app > library"], fixed_versions=["2.1"]),
            # Same package and title but a different vulnerability: retain it.
            audit.finding("snyk", "library", "SNYK-456", "Issue", "high", cves=["CVE-2026-54321"]),
            # A shared CVE in another package must not collapse the packages.
            audit.finding("snyk", "other", "SNYK-123", "Issue", "high", cves=["CVE-2026-12345"]),
        ]
        merged = audit.deduplicate_findings(rows)
        self.assertEqual(len(merged), 3)
        common = next(r for r in merged if len(r["scanners"]) == 3)
        self.assertEqual(common["severity"], "critical")
        self.assertEqual(common["ghsas"], ["GHSA-abcd-1234-5678"])
        self.assertEqual(common["fixed_versions"], ["2.1", ">=2.0"])
        self.assertEqual(common["severities_by_scanner"]["yarn"], ["medium"])
        self.assertEqual(len(common["source_findings"]), 3)
        self.assertEqual(len(common["paths"]), 2)

    def test_unmatched_identifiers_are_not_merged_by_title(self):
        rows = [audit.finding(s, "library", ident, "Same title", "high")
                for s, ident in (("npm", "111"), ("snyk", "SNYK-111"))]
        self.assertEqual(len(audit.deduplicate_findings(rows)), 2)

    def test_medium_and_moderate_native_counts_are_normalized_to_medium(self):
        self.assertEqual(audit.severity_counts({"moderate": 2, "medium": 1, "total": 3}),
                         {"medium": 3, "total": 3})
        rows = audit.aggregate([audit.finding("npm", "library", "1", "Issue", "moderate")])
        self.assertEqual(rows[0]["severity"], "medium")

    def test_scanner_selection_excludes_stale_raw_files_and_never_runs_other_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"name":"test"}')
            raw = root / "reports" / "raw"
            raw.mkdir(parents=True)
            (raw / audit.RAW_NAMES["npm"]).write_text(json.dumps(
                {"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}))
            # Existing garbage from unselected scanners must be ignored.
            (raw / audit.RAW_NAMES["snyk"]).write_text("stale, invalid JSON")
            with mock.patch.object(audit, "run_scanner", return_value={"exit_code": 0}) as run:
                with mock.patch("sys.argv", ["audit_dependencies.py", "--scanners", "npm", "npm",
                                             "--project", str(root)]):
                    self.assertEqual(audit.main(), 0)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], "npm")
            report = json.loads((root / "reports/vulnerabilities.json").read_text())
            self.assertEqual(report["selected_scanners"], ["npm"])
            self.assertEqual(list(report["scans"]), ["npm"])
            # Replay has the same selection and never invokes subprocess scanners.
            with mock.patch.object(audit, "run_scanner") as run:
                with mock.patch("sys.argv", ["audit_dependencies.py", "--scanners", "npm", "--parse-only",
                                             "--project", str(root)]):
                    self.assertEqual(audit.main(), 0)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
