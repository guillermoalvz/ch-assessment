"""Checks for accurate generated summaries, comparisons, and Markdown safety."""

import unittest
import contextlib
import io
import json
from pathlib import Path
import tempfile
from unittest import mock

import audit_dependencies as audit
import generate_audit_report as markdown


def snapshot(findings, status="completed", scanner="npm"):
    return {"generated_at": "2026-10-07T19:00:00+00:00", "project": "/saved/project",
            "scans": {scanner: {"status": status, "version": "1", "exit_code": 1 if findings else 0,
                                 "reported_counts": {"moderate": len(findings)},
                                 "count_unit": "vulnerable packages"}},
            "declared_dependencies": {"dependencies": {"library": "1.0"}},
            "resolved_dependencies": {"dependencies": {"library": "1.0"}},
            "findings": findings}


class MarkdownReportTests(unittest.TestCase):
    def test_generates_concise_counts_dependencies_and_parent_upgrade_suggestions(self):
        row = audit.finding("npm", "library", "GHSA-abcd-1234-5678", "Prototype pollution", "high",
                            paths=["app > library"], fixed_versions=["2.0"],
                            remediation=["Upgrade parent to 3.0"], fix_available=True)
        document = markdown.render_report(snapshot([row]))
        for text in ["## Scan results", "## Dependency versions", "## Priority packages",
                     "Upgrade parent to 3.0", "| library |", "Installed"]:
            self.assertIn(text, document)
        self.assertNotIn("## Observed dependency paths", document)
        self.assertNotIn("# Remediation comparison", document)
        self.assertIn("JSON and CSV retain all advisory IDs, titles, paths", document)

    def test_completed_comparison_counts_only_removed_advisory_ids(self):
        old = [audit.finding("npm", "library", ident, "Issue", level)
               for ident, level in (("one", "high"), ("two", "medium"))]
        new = [audit.finding("npm", "library", ident, "Issue", "medium") for ident in ("two", "new")]
        self.assertEqual(markdown.comparison_rows(snapshot(old), snapshot(new)),
                         [["npm", "completed", 1, 1, 1, 1]])
        rendered = markdown.render_report(snapshot(old), snapshot(new))
        self.assertIn("# Remediation comparison", rendered)
        self.assertIn("Newly reported", rendered)

    def test_failed_or_missing_comparison_scan_does_not_claim_fixes(self):
        baseline = snapshot([audit.finding("npm", "library", "1", "Issue", "high")])
        for candidate in (snapshot([], status="error"), snapshot([], scanner="snyk")):
            rows = markdown.comparison_rows(baseline, candidate)
            self.assertEqual(rows[0][2:], ["Unavailable"] * 4)
            rendered = markdown.render_report(baseline, candidate)
            self.assertIn("Incomplete assessment", rendered)
            self.assertNotIn("**No unresolved findings:", rendered)
        failed = markdown.render_report(snapshot([], status="error"))
        self.assertIn("Incomplete assessment", failed)
        self.assertIn("failed scans are not clean results", failed)

    def test_legacy_moderate_findings_render_as_medium(self):
        row = audit.finding("npm", "library", "1", "Issue", "medium")
        row["severity"] = "moderate"
        document = markdown.render_report(snapshot([row]))
        self.assertIn("| medium |", document)
        self.assertNotIn("| moderate |", document)

    def test_remaining_unfixable_findings_precede_fixable_and_include_new_issues(self):
        old = audit.finding("npm", "blocked", "old", "Unpatched issue", "low", fix_available=False)
        fixable = audit.finding("npm", "fixable", "new", "New issue", "critical",
                               fixed_versions=["2.0"], remediation=["Upgrade to 2.0"], fix_available=True)
        document = markdown.render_report(snapshot([old]), snapshot([old, fixable]))
        self.assertLess(document.index("Unpatched issue"), document.index("New issue"))
        self.assertLess(document.index("Unpatched issue"), document.index("## Scan results"))
        self.assertIn("1 with no fix reported", document)
        self.assertIn("| npm | 1 | 2 | 0 | 1 | 1 |", document)

    def test_missing_fix_metadata_and_patched_version_are_not_no_fix(self):
        unknown = audit.finding("npm", "unknown", "one", "Unknown issue", "high")
        del unknown["fix_available"]
        patched = audit.finding("npm", "patched", "two", "Known patch", "high",
                                fixed_versions=["2.0"], fix_available=False)
        document = markdown.render_report(snapshot([]), snapshot([unknown, patched]))
        self.assertIn("0 with no fix reported; 1 with unknown fix availability", document)
        self.assertIn("## Fix availability unknown", document)
        self.assertIn("Known patch", document)
        self.assertEqual(markdown.fix_status(patched), "Patched version reported; no upgrade path")

    def test_shared_identifier_with_one_scanner_fix_is_not_unfixable(self):
        no_fix = audit.finding("npm", "library", "GHSA-abcd-1234-5678", "Issue", "high", fix_available=False)
        fix = audit.finding("yarn", "library", "GHSA-abcd-1234-5678", "Issue", "high", fix_available=True)
        candidate = snapshot([no_fix])
        candidate["scans"].update(snapshot([fix], scanner="yarn")["scans"])
        candidate["findings"].append(fix)
        document = markdown.render_report(candidate, candidate)
        self.assertIn("1 merged advisory groups; 0 with no fix reported", document)

    def test_failed_partial_scan_does_not_establish_complete_findings(self):
        row = audit.finding("npm", "library", "one", "Partial finding", "high", fix_available=False)
        document = markdown.render_report(snapshot([row]), snapshot([row], status="error"))
        self.assertIn("Incomplete assessment", document)
        self.assertNotIn("Partial finding", document)
        self.assertIn("| npm | 1 | error | Unavailable | Unavailable | Unavailable |", document)

    def test_additional_failed_candidate_scanner_prevents_clean_result(self):
        candidate = snapshot([])
        candidate["scans"]["yarn"] = {"status": "error", "error": "Timed out"}
        document = markdown.render_report(snapshot([]), candidate)
        self.assertIn("proposal yarn: Timed out", document)
        self.assertNotIn("**No unresolved findings:", document)

    def test_clean_comparison_omits_resolved_findings_and_unchanged_versions(self):
        old = audit.finding("npm", "library", "one", "Old vulnerability", "high", fix_available=False)
        document = markdown.render_report(snapshot([old]), snapshot([]))
        self.assertIn("**No unresolved findings:", document)
        self.assertNotIn("Old vulnerability", document)
        self.assertNotIn("| library |", document)
        self.assertIn("| npm | 1 | 0 | 1 | 0 | 0 |", document)

    def test_cli_defaults_place_reports_beside_json_with_distinct_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "reports" / "vulnerabilities.json"
            candidate = root / "remediation" / "reports" / "vulnerabilities.json"
            for path in (baseline, candidate):
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(snapshot([])))
            args = ["generate_audit_report.py", "--input", str(baseline)]
            for extra, name in [([], "AUDIT_REPORT.md"),
                                (["--comparison", str(candidate)], "REMEDIATION_COMPARISON.md")]:
                with mock.patch("sys.argv", args + extra), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(markdown.main(), 0)
                document = (baseline.parent / name).read_text()
                self.assertIn("[JSON](vulnerabilities.json)", document)
                if extra:
                    self.assertIn("[JSON](../remediation/reports/vulnerabilities.json)", document)
            with mock.patch("sys.argv", args + ["--output", str(baseline)]), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(markdown.main(), 2)
            self.assertIsInstance(json.loads(baseline.read_text()), dict)

    def test_untrusted_markdown_and_links_are_escaped(self):
        row = audit.finding("npm", "library", "1", "<script>bad</script>|[click](evil)\nheading", "high",
                            url="javascript:alert(1)")
        document = markdown.render_report(snapshot([row]))
        self.assertNotIn("<script>", document)
        self.assertNotIn("](javascript:", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn("\\|", document)
        self.assertIn("\\[click\\]", document)


if __name__ == "__main__":
    unittest.main()
