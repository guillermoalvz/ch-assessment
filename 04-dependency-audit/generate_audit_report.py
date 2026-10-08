#!/usr/bin/env python3
"""Generate factual Markdown from saved vulnerability JSON; no scans or AI calls."""

import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlsplit

from audit_dependencies import aggregate, deduplicate_findings


def cell(value):
    """Escape scanner-controlled content before placing it in a Markdown table."""
    if value is None:
        return "Unavailable"
    if isinstance(value, (list, tuple)):
        value = "; ".join(str(item) for item in value) or "—"
    value = html.escape(str(value), quote=False)
    return re.sub(r"([\\`*_{}\[\]()|])", r"\\\1", value).replace("\r", "").replace("\n", "<br>")


def table(headers, rows):
    return ("| " + " | ".join(cell(h) for h in headers) + " |\n"
            + "| " + " | ".join("---" for _ in headers) + " |\n"
            + "".join("| " + " | ".join(cell(v) for v in row) + " |\n" for row in rows)
            + "\n")


def advisory_links(rows):
    links = []
    for row in rows:
        label = cell(f"{row['scanner']}: {row['advisory_id']}")
        url = row.get("url", "")
        parsed = urlsplit(url)
        if parsed.scheme in ("https", "http") and parsed.netloc:
            links.append(f"[{label}]({quote(url, safe=':/?&=#%+-._~')})")
        else:
            links.append(label)
    return "; ".join(links)


def load_report(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("scans"), dict) or not data["scans"]:
        raise ValueError(f"{path}: missing or empty scans object")
    if not isinstance(data.get("findings"), list):
        raise ValueError(f"{path}: missing findings list")
    return normalize_report(data)


def normalize_report(data):
    """Reuse scanner normalization/dedup, including for older report snapshots."""
    result = dict(data)
    result["findings"] = aggregate([
        dict(row, fix_available=row.get("fix_available")) for row in data["findings"]
    ])
    if any(row["scanner"] not in data["scans"] for row in result["findings"]):
        raise ValueError("Finding references a scanner absent from scans metadata")
    result["deduplicated_findings"] = deduplicate_findings(result["findings"])
    return result


def scanner_rows(report, scanner):
    return [r for r in report["findings"] if r["scanner"] == scanner]


def comparison_rows(baseline, candidate):
    """Only completed scans can establish disappearance of a finding."""
    rows = []
    for scanner in baseline["scans"]:
        old_scan = baseline["scans"][scanner]
        new_scan = candidate["scans"].get(scanner, {})
        if old_scan.get("status") != "completed" or new_scan.get("status") != "completed":
            rows.append([scanner, new_scan.get("status", "not selected"),
                         "Unavailable", "Unavailable", "Unavailable", "Unavailable"])
            continue
        old = {(r["package"], r["advisory_id"]): r for r in scanner_rows(baseline, scanner)}
        new = {(r["package"], r["advisory_id"]): r for r in scanner_rows(candidate, scanner)}
        removed = old.keys() - new.keys()
        rows.append([scanner, "completed", len(removed),
                     sum(old[key]["severity"] in ("high", "critical") for key in removed),
                     len(old.keys() & new.keys()), len(new.keys() - old.keys())])
    return rows


def completed_report(report):
    """Partial findings cannot establish complete counts or successful remediation."""
    result = dict(report)
    result["findings"] = [row for row in report["findings"]
                          if report["scans"][row["scanner"]].get("status") == "completed"]
    return normalize_report(result)


def fix_status(item):
    """Distinguish missing fix metadata from an explicit negative scanner result."""
    sources = item.get("source_findings", [item])
    if any(row.get("fix_available") is True for row in sources):
        return "Fix reported"
    if any(row.get("fixed_versions") for row in sources):
        return "Patched version reported; no upgrade path"
    if all(row.get("fix_available") is False for row in sources):
        return "No fix reported"
    return "Availability unknown"


def finding_table(items):
    """Keep individual unresolved advisories visible, with links to source evidence."""
    if not items:
        return ""
    parts = ["| Severity | Package / versions | Issue | Fix information | Evidence |\n"
             "| --- | --- | --- | --- | --- |\n"]
    for item in items:
        sources = item["source_findings"]
        suggestion = item["remediation"] or item["fixed_versions"] or [fix_status(item)]
        # One evidence link keeps the summary short; exports retain every alias/path.
        evidence = next((row for row in sources if row.get("url")), sources[0])
        parts.append("| " + " | ".join([
            cell(item["severity"]), cell(item["package"] + " " + ", ".join(item["versions"])),
            cell(item["title"]), cell(suggestion), advisory_links([evidence])]) + " |\n")
    return "".join(parts) + "\n"


def evidence_links(input_path, output_path):
    def link(label, path):
        relative = os.path.relpath(path, output_path.parent)
        return f"[{label}]({quote(relative, safe='/.-_')})"
    return ", ".join([link("JSON", input_path),
                      link("CSV", input_path.with_name("vulnerabilities.csv")),
                      link("merged CSV", input_path.with_name("vulnerabilities-dedup.csv")),
                      link("raw scans and metadata", input_path.parent / "raw")])


def render_report(report, comparison=None, *, baseline_evidence=None, candidate_evidence=None):
    report = normalize_report(report)
    comparison = normalize_report(comparison) if comparison is not None else None
    baseline = completed_report(report)
    target = completed_report(comparison) if comparison is not None else baseline
    items = target["deduplicated_findings"]
    no_fix = [row for row in items if fix_status(row) == "No fix reported"]
    unknown = [row for row in items if fix_status(row) == "Availability unknown"]
    expected = sorted(set(report["scans"]) | (set(comparison["scans"]) if comparison is not None else set()))
    incomplete = []
    for label, snapshot in [("baseline", report)] + ([("proposal", comparison)] if comparison is not None else []):
        for scanner in expected:
            scan = snapshot["scans"].get(scanner, {})
            if scan.get("status") != "completed":
                incomplete.append(f"{label} {scanner}: " + scan.get("error", scan.get("status", "not selected")))

    title = "Remediation comparison" if comparison is not None else "Dependency audit"
    parts = [f"# {title}\n\n"]
    if incomplete:
        parts.append("**Incomplete assessment:** " + cell(incomplete)
                     + ". Counts cover completed scans only; failed scans are not clean results.\n\n")
    elif comparison is not None and not items:
        parts.append("**No unresolved findings:** all selected proposal scans completed with zero findings.\n\n")
    else:
        parts.append(f"**{len(items)} merged advisory groups; {len(no_fix)} with no fix reported; "
                     f"{len(unknown)} with unknown fix availability.**\n\n")

    parts.append("## Unresolved findings without a reported fix\n\n")
    if no_fix:
        parts.append(finding_table(no_fix))
    else:
        parts.append("None in the completed scans.\n\n")
    parts.append("“No fix reported” means no scanner reported an available fix or patched version; "
                 "it does not prove that no fix exists. Review affected parent dependencies or replacement packages.\n\n")
    if unknown:
        parts.append("## Fix availability unknown\n\n" + finding_table(unknown))
    if comparison is not None:
        fixable = [row for row in items if fix_status(row) not in ("No fix reported", "Availability unknown")]
        if fixable:
            parts.append("## Other unresolved findings\n\n")
            parts.append("These remain in the proposal despite a reported fix or patched version.\n\n")
            parts.append(finding_table(fixable))

    parts.append("## Scan results\n\n")
    if comparison is not None:
        rows = []
        changes = {row[0]: row for row in comparison_rows(baseline, target)}
        for scanner in expected:
            before = report["scans"].get(scanner, {})
            after = comparison["scans"].get(scanner, {})
            valid_before = before.get("status") == "completed"
            valid_after = after.get("status") == "completed"
            counts = changes.get(scanner, [scanner, "not selected", *(["Unavailable"] * 4)])
            rows.append([scanner,
                         len(scanner_rows(baseline, scanner)) if valid_before else before.get("status", "not selected"),
                         len(scanner_rows(target, scanner)) if valid_after else after.get("status", "not selected"),
                         counts[2], counts[4], counts[5]])
        parts.append(table(["Scanner", "Baseline advisories", "Proposal advisories", "No longer reported",
                            "Still reported", "Newly reported"], rows))
        parts.append("Changes match package/advisory IDs within each scanner. Missing or failed scans "
                     "cannot establish that a finding was removed.\n\n")
    else:
        rows = []
        for scanner, scan in report["scans"].items():
            source = scanner_rows(baseline, scanner)
            counts = Counter(row["severity"] for row in source)
            complete = scan.get("status") == "completed"
            rows.append([scanner, scan.get("status", "unknown"), len(source) if complete else "Unavailable",
                         counts["high"] + counts["critical"] if complete else "Unavailable",
                         sum(fix_status(row) == "No fix reported" for row in source) if complete else "Unavailable"])
        parts.append(table(["Scanner", "Status", "Advisories", "High/critical", "No fix reported"], rows))

        priority = [row for row in items if row["severity"] in ("high", "critical")]
        parts.append("## Priority packages\n\n")
        packages = sorted({row["package"] for row in priority})
        rows = []
        for package in packages:
            group = [row for row in priority if row["package"] == package]
            versions = sorted({version for row in group for version in row["versions"]})
            sources = [source for row in group for source in row["source_findings"]]
            # Prefer parent-upgrade suggestions from npm; detailed alternatives stay in JSON.
            suggestions = sorted({action for source in sources if source["scanner"] == "npm"
                                  for action in source["remediation"]})
            if not suggestions:
                suggestions = sorted({action for source in sources for action in source["remediation"]})
            rows.append([package, versions, len(group), suggestions or "See JSON for advisory details"])
        parts.append(table(["Package", "Installed versions", "High/critical groups", "Scanner suggestions"], rows)
                     if rows else "No high/critical findings in the completed scans.\n\n")

    parts.append("Counts overlap across scanners. Shared GHSA/CVE IDs or advisory URLs merge findings; "
                 "the highest source severity is retained. `moderate` is normalized to `medium`.\n\n")

    parts.append("## Dependency versions\n\n")
    dependency_rows = []
    for section in ("dependencies", "devDependencies"):
        declared = report.get("declared_dependencies", {}).get(section, {})
        proposed = comparison.get("declared_dependencies", {}).get(section, {}) if comparison is not None else {}
        for name in sorted(set(declared) | set(proposed)):
            before = report.get("resolved_dependencies", {}).get(section, {}).get(name)
            if comparison is not None:
                after = comparison.get("resolved_dependencies", {}).get(section, {}).get(name)
                if before is not None and before == after and declared.get(name) == proposed.get(name):
                    continue
                dependency_rows.append([name, before if name in declared else "Not declared",
                                        after if name in proposed else "Not declared"])
            else:
                dependency_rows.append([name, declared.get(name), before])
    headers = ["Package", "Installed baseline", "Installed proposal"] if comparison is not None else ["Package", "Declared", "Installed"]
    parts.append(table(headers, dependency_rows) if dependency_rows else "No dependency changes or version data recorded.\n\n")
    parts.append("Installed versions come from saved lockfile snapshots; missing versions are unavailable.\n\n")

    parts.append("## Evidence and limits\n\n")
    parts.append(f"Baseline snapshot: {cell(report.get('generated_at'))}.\n\n")
    if baseline_evidence:
        parts.append("Baseline evidence: " + baseline_evidence + ".\n\n")
    if comparison is not None:
        parts.append(f"Proposal snapshot: {cell(comparison.get('generated_at'))}.\n\n")
        if candidate_evidence:
            parts.append("Proposal evidence: " + candidate_evidence + ".\n\n")
    parts.append("JSON and CSV retain all advisory IDs, titles, paths, severities, and fix suggestions; "
                 "raw metadata retains commands, versions, times, and exit codes. A reported fix can apply to "
                 "only some dependency paths. Clean scans do not establish application compatibility; "
                 "test major upgrades and rescan the chosen lockfile.\n")
    return "".join(parts)


def default_output(input_path, comparison=None):
    name = "REMEDIATION_COMPARISON.md" if comparison is not None else "AUDIT_REPORT.md"
    return input_path.with_name(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).resolve().parent / "reports/vulnerabilities.json")
    parser.add_argument("--output", type=Path,
                        help="Default: AUDIT_REPORT.md, or REMEDIATION_COMPARISON.md with --comparison, beside the input JSON")
    parser.add_argument("--comparison", type=Path, help="Optional candidate vulnerabilities.json")
    args = parser.parse_args()
    try:
        baseline = load_report(args.input)
        candidate = load_report(args.comparison) if args.comparison else None
        output = args.output or default_output(args.input, args.comparison)
        rendered = render_report(
            baseline, candidate, baseline_evidence=evidence_links(args.input, output),
            candidate_evidence=evidence_links(args.comparison, output) if args.comparison else None)
        if output.resolve() in {p.resolve() for p in (args.input, args.comparison) if p is not None}:
            raise ValueError("Output must not overwrite an input JSON report")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Report generation failed: {exc}", file=sys.stderr)
        return 2
    print(f"Markdown report: {output.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
