#!/usr/bin/env python3
"""Run selected npm, Yarn Classic and Snyk audits using the standard library.

Lockfiles and node_modules must already exist. No dependency updates or package
scripts are run. Each report row is one (scanner, package, advisory), with paths
aggregated. A second CSV merges shared advisory identifiers across scanners;
different vulnerabilities in the same library remain separate.
"""

import argparse
import csv
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
COMMANDS = {
    "npm": ["npm", "audit", "--json", "--cache", ".scan/npm-cache"],
    "yarn": ["yarn", "audit", "--json", "--registry", "https://registry.npmjs.org"],
    "snyk": ["snyk", "test", "--file=package.json", "--package-manager=npm", "--dev", "--json"],
}
RAW_NAMES = {"npm": "npm-audit.json", "yarn": "yarn-audit.jsonl", "snyk": "snyk-test.json"}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def run_scanner(scanner, project, raw, timeout):
    """Capture findings exits as data; distinguish missing tools and timeouts."""
    command = COMMANDS[scanner]
    start = time.monotonic()
    meta = {"command": command, "started_at": timestamp()}
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    try:
        version = subprocess.run([command[0], "--version"], cwd=project,
                                 capture_output=True, text=True, timeout=30, env=env)
        meta["version"] = version.stdout.strip()
        result = subprocess.run(command, cwd=project, capture_output=True,
                                text=True, timeout=timeout, env=env)
        stdout, stderr = result.stdout, result.stderr
        meta["exit_code"] = result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = text(exc.stdout), text(exc.stderr)
        meta.update(exit_code=None, execution_error=f"Timed out after {exc.timeout}s")
    except OSError as exc:
        stdout, stderr = "", str(exc)
        meta.update(exit_code=None, execution_error=str(exc))
    (raw / RAW_NAMES[scanner]).write_text(stdout)
    (raw / f"{scanner}.stderr.log").write_text(stderr)
    meta["duration_seconds"] = round(time.monotonic() - start, 3)
    return meta


def severity(value):
    value = str(value).lower()
    value = "medium" if value == "moderate" else value
    if value not in SEVERITIES:
        raise ValueError(f"Unsupported severity: {value}")
    return value


def severity_counts(counts):
    """Normalize native npm/Yarn counts without changing their raw scan files."""
    result = {}
    for level, count in counts.items():
        key = "total" if level == "total" else severity(level)
        result[key] = result.get(key, 0) + count
    return result


def finding(scanner, package, advisory_id, title, level, **kwargs):
    row = {"scanner": scanner, "package": package, "advisory_id": str(advisory_id),
           "title": title.strip(), "severity": severity(level), "versions": [],
           "paths": [], "cves": [], "ghsas": [], "fixed_versions": [], "fix_available": None,
           "remediation": [], "url": "", "vulnerable_range": ""}
    row.update(kwargs)
    return row


def parse_npm(data, lock):
    if not isinstance(data, dict) or data.get("error"):
        raise ValueError(f"npm scanner error: {data.get('error') if isinstance(data, dict) else data}")
    if not isinstance(data.get("vulnerabilities"), dict) or "metadata" not in data:
        raise ValueError("Missing npm vulnerabilities/metadata; not a completed audit")
    rows = []
    packages = lock.get("packages", {})
    for name, affected in data["vulnerabilities"].items():
        fix = affected.get("fixAvailable", False)
        remediation = []
        if isinstance(fix, dict):
            remediation = [f"Upgrade {fix['name']} to {fix['version']}"
                           + (" (major version change)" if fix.get("isSemVerMajor") else "")]
        elif fix:
            remediation = ["npm audit fix (compatible dependency update)"]
        for advisory in affected.get("via", []):
            # String entries are inherited vulnerabilities, not extra advisories.
            if not isinstance(advisory, dict):
                continue
            url = advisory.get("url", "")
            rows.append(finding(
                "npm", name, url.rsplit("/", 1)[-1] or advisory["source"],
                advisory["title"], advisory["severity"], url=url,
                cves=advisory.get("cves", []),
                vulnerable_range=advisory.get("range", ""),
                versions=sorted({packages[node]["version"] for node in affected.get("nodes", [])
                                 if node in packages and "version" in packages[node]}),
                paths=affected.get("nodes", []), fix_available=bool(fix),
                remediation=remediation))
    return rows, {"count_unit": "vulnerable packages (including inherited vulnerabilities)",
                  "reported_counts": severity_counts(data["metadata"]["vulnerabilities"]),
                  "vulnerable_packages": {
                      name: {"severity": severity(v.get("severity", "info")),
                             "isDirect": v.get("isDirect", False),
                             "fixAvailable": v.get("fixAvailable", False),
                             "nodes": v.get("nodes", [])}
                      for name, v in data["vulnerabilities"].items()}}


def parse_yarn(contents):
    rows, summary = [], None
    for line in contents.splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("type") == "error":
            raise ValueError(f"Yarn scanner error: {event.get('data')}")
        if event.get("type") == "auditSummary":
            summary = event["data"]
        if event.get("type") != "auditAdvisory":
            continue
        advisory = event["data"]["advisory"]
        patched = advisory.get("patched_versions", "")
        rows.append(finding(
            "yarn", advisory["module_name"],
            advisory.get("github_advisory_id") or advisory["id"],
            advisory["title"], advisory["severity"],
            versions=[f["version"] for f in advisory.get("findings", [])],
            paths=[p for f in advisory.get("findings", []) for p in f.get("paths", [])],
            cves=advisory.get("cves", []), url=advisory.get("url", ""),
            vulnerable_range=advisory.get("vulnerable_versions", ""),
            fixed_versions=[patched] if patched else [],
            fix_available=bool(patched and patched not in ("<0.0.0", "*")),
            remediation=[advisory["recommendation"]] if advisory.get("recommendation") else []))
    if summary is None:
        raise ValueError("Missing Yarn auditSummary; scan may be incomplete")
    return rows, {"count_unit": "advisory/dependency-path occurrences",
                  "reported_counts": severity_counts(summary["vulnerabilities"])}


def parse_snyk(data):
    if not isinstance(data, dict) or data.get("error"):
        raise ValueError(f"Snyk scanner error: {data.get('error') if isinstance(data, dict) else data}")
    if "ok" not in data or ("vulnerabilities" not in data and data["ok"] is not True):
        raise ValueError("Missing Snyk result fields; not a completed test")
    rows = []
    for advisory in data.get("vulnerabilities", []):
        identifiers = advisory.get("identifiers", {})
        upgrade = [item for item in advisory.get("upgradePath", []) if isinstance(item, str)]
        rows.append(finding(
            "snyk", advisory["name"], advisory["id"], advisory["title"],
            advisory["severity"], versions=[advisory["version"]],
            paths=[" > ".join(advisory.get("from", []))],
            cves=identifiers.get("CVE", []), ghsas=identifiers.get("GHSA", []),
            fixed_versions=advisory.get("fixedIn", []),
            vulnerable_range=json.dumps(advisory.get("semver", {}).get("vulnerable", [])),
            url="https://security.snyk.io/vuln/" + advisory["id"],
            fix_available=bool(advisory.get("isUpgradable") or advisory.get("isPatchable")),
            remediation=["Upgrade path: " + " > ".join(upgrade)] if upgrade else []))
    return rows, {"count_unit": "unique Snyk advisories and vulnerable dependency paths",
                  "reported_unique_count": data.get("uniqueCount", 0),
                  "reported_summary": data.get("summary", ""),
                  "upgradeable_path_occurrences": sum(bool(v.get("isUpgradable"))
                                                       for v in data.get("vulnerabilities", [])),
                  "patchable_path_occurrences": sum(bool(v.get("isPatchable"))
                                                     for v in data.get("vulnerabilities", []))}


def aggregate(rows):
    unique = {}
    for row in rows:
        row = dict(row, severity=severity(row["severity"]), ghsas=row.get("ghsas", []))
        key = (row["scanner"], row["package"], row["advisory_id"])
        if key not in unique:
            unique[key] = row.copy()
        else:
            current = unique[key]
            for field in ("versions", "paths", "cves", "ghsas", "fixed_versions", "remediation"):
                current[field] = current[field] + row[field]
            current["fix_available"] = current["fix_available"] or row["fix_available"]
            if SEVERITIES[row["severity"]] > SEVERITIES[current["severity"]]:
                current["severity"] = row["severity"]
    for row in unique.values():
        for field in ("versions", "paths", "cves", "ghsas", "fixed_versions", "remediation"):
            row[field] = sorted(set(row[field]))
    return sorted(unique.values(), key=lambda r: (-SEVERITIES[r["severity"]],
                                                 r["package"], r["scanner"], r["advisory_id"]))


def advisory_tokens(row):
    """Use published identifiers, never titles, to match the same vulnerability."""
    tokens = {f"source:{row['scanner']}:{row['advisory_id']}"}
    identifiers = [row["advisory_id"], row.get("url", ""),
                   *row.get("cves", []), *row.get("ghsas", [])]
    for value in identifiers:
        tokens.update(token.upper() for token in re.findall(
            r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+", value, re.I))
    if row.get("url"):
        tokens.add("url:" + row["url"].rstrip("/"))
    return tokens


def deduplicate_findings(rows):
    """Merge package/advisory aliases across scanners, including CVE bridges.

    Unmatched identifiers remain separate. Different vulnerabilities in the same
    package must not be collapsed. Source evidence and rating differences survive.
    """
    rows = aggregate(rows)
    parents = list(range(len(rows)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    aliases = {}
    for index, row in enumerate(rows):
        for token in advisory_tokens(row):
            key = (row["package"], token)
            if key in aliases:
                parents[root(index)] = root(aliases[key])
            else:
                aliases[key] = index
    groups = {}
    for index, row in enumerate(rows):
        groups.setdefault(root(index), []).append(row)
    findings = []
    for group in groups.values():
        item = {"package": group[0]["package"], "title": group[0]["title"],
                "severity": max((r["severity"] for r in group), key=SEVERITIES.get),
                "scanners": sorted({r["scanner"] for r in group}),
                "advisory_ids": sorted({f"{r['scanner']}:{r['advisory_id']}" for r in group}),
                "titles": sorted({r["title"] for r in group}),
                "urls": sorted({r["url"] for r in group if r.get("url")}),
                "vulnerable_ranges": sorted({f"{r['scanner']}: {r['vulnerable_range']}"
                                             for r in group if r.get("vulnerable_range")}),
                "fix_available": any(r["fix_available"] for r in group),
                "severities_by_scanner": {s: sorted({r["severity"] for r in group if r["scanner"] == s},
                                                     key=SEVERITIES.get)
                                          for s in sorted({r["scanner"] for r in group})},
                "source_findings": group}
        for field in ("versions", "paths", "cves", "ghsas", "fixed_versions", "remediation"):
            item[field] = sorted({value for row in group for value in row.get(field, [])})
        # npm/Yarn often expose GHSA only through the advisory ID or URL.
        item["ghsas"] = sorted({"GHSA-" + token[5:].lower() for row in group
                                for token in advisory_tokens(row) if token.startswith("GHSA-")})
        findings.append(item)
    return sorted(findings, key=lambda r: (-SEVERITIES[r["severity"]], r["package"], r["advisory_ids"]))


def deduplicated_summary(rows):
    return {"advisories": len(rows), "packages": len({r['package'] for r in rows}),
            "by_severity": dict(Counter(r["severity"] for r in rows)),
            "high_critical": sum(r["severity"] in ("high", "critical") for r in rows),
            "with_any_scanner_fix": sum(bool(r["fix_available"]) for r in rows)}


def build_report(project, output, metadata, scanners=None):
    lock_path = project / "package-lock.json"
    lock = json.loads(lock_path.read_text()) if lock_path.exists() else {}
    rows, scans = [], {}
    for scanner in (scanners if scanners is not None else COMMANDS):
        scan = dict(metadata.get(scanner, {}))
        try:
            if scan.get("execution_error"):
                raise ValueError(scan["execution_error"])
            contents = (output / "raw" / RAW_NAMES[scanner]).read_text()
            if scanner == "npm":
                parsed, details = parse_npm(json.loads(contents), lock)
            elif scanner == "yarn":
                parsed, details = parse_yarn(contents)
            else:
                parsed, details = parse_snyk(json.loads(contents))
            code = scan.get("exit_code")
            allowed = {0, 1} if scanner in ("npm", "snyk") else set(range(32))
            if code is not None and code not in allowed:
                raise ValueError(f"Unexpected scanner exit code {code}")
            unique = aggregate(parsed)
            if code is not None and ((code == 0) != (len(unique) == 0)):
                raise ValueError("Exit code contradicts parsed vulnerability result")
            scan.update(details, status="completed",
                        parsed_path_occurrences=len(parsed), unique_advisories=len(unique),
                        unique_advisories_by_severity=dict(Counter(r["severity"] for r in unique)),
                        high_critical_unique_advisories=sum(r["severity"] in ("high", "critical")
                                                           for r in unique),
                        advisories_with_any_scanner_fix=sum(bool(r["fix_available"]) for r in unique),
                        high_critical_with_any_scanner_fix=sum(bool(r["fix_available"])
                            and r["severity"] in ("high", "critical") for r in unique))
            rows.extend(unique)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            scan.update(status="error", error=str(exc))
        scans[scanner] = scan
    manifest = json.loads((project / "package.json").read_text())
    hashes = {name: hashlib.sha256((project / name).read_bytes()).hexdigest()
              for name in ("package.json", "package-lock.json", "yarn.lock")
              if (project / name).exists()}
    resolved = {section: {name: lock.get("packages", {}).get("node_modules/" + name, {}).get("version")
                          for name in manifest.get(section, {})}
                for section in ("dependencies", "devDependencies")}
    findings = aggregate(rows)
    deduplicated = deduplicate_findings(findings)
    return {"generated_at": timestamp(), "project": str(project), "selected_scanners": list(scans),
            "manifest_sha256_and_lockfile_sha256": hashes,
            "declared_dependencies": {key: manifest.get(key, {})
                                      for key in ("dependencies", "devDependencies")},
            "resolved_dependencies": resolved,
            "counting_note": "Rows are unique per scanner/package/advisory; do not add scanner totals. "
                             "Fix counts mean at least one path has scanner remediation, not all paths.",
            "deduplication_note": "Merge the same package only on shared GHSA/CVE identifiers or exact "
                                  "advisory URLs, including transitive alias matches. Unmatched advisories "
                                  "remain separate. Use the highest severity and retain source evidence; "
                                  "counts may include unmatched aliases of the same vulnerability.",
            "scans": scans, "findings": findings,
            "deduplicated_findings": deduplicated,
            "deduplicated_summary": deduplicated_summary(deduplicated)}


def write_csv(path, findings, fields):
    """Share serialization and formula protection across both CSV exports."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding_row in findings:
            row = {key: finding_row[key] for key in fields}
            for key, value in row.items():
                if isinstance(value, list):
                    row[key] = " | ".join(value)
                elif isinstance(value, dict):
                    row[key] = json.dumps(value, sort_keys=True)
                # Prevent spreadsheet formulas if a registry title/path is hostile.
                if isinstance(row[key], str) and row[key].lstrip().startswith(("=", "+", "-", "@")):
                    row[key] = "'" + row[key]
            writer.writerow(row)


def save_report(report, output):
    deduplicated = deduplicate_findings(report["findings"])
    report.update(deduplicated_findings=deduplicated,
                  deduplicated_summary=deduplicated_summary(deduplicated))
    (output / "vulnerabilities.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    fields = ["scanner", "package", "versions", "advisory_id", "cves", "severity",
              "title", "vulnerable_range", "fixed_versions", "fix_available",
              "paths", "remediation", "url"]
    write_csv(output / "vulnerabilities.csv", report["findings"], fields)
    dedup_fields = ["scanners", "package", "versions", "advisory_ids", "cves", "ghsas", "severity",
                    "severities_by_scanner", "titles", "vulnerable_ranges", "fixed_versions",
                    "fix_available", "paths", "remediation", "urls"]
    write_csv(output / "vulnerabilities-dedup.csv", deduplicated, dedup_fields)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--output", type=Path, help="Default: PROJECT/reports")
    parser.add_argument("--scanners", nargs="+", choices=COMMANDS, required=True,
                        help="Scanners to run/replay, e.g. --scanners npm snyk")
    parser.add_argument("--parse-only", action="store_true", help="Parse saved raw output without network")
    parser.add_argument("--timeout", type=int, default=180, help="Seconds per scanner (default: 180)")
    parser.add_argument("--fail-on", choices=SEVERITIES, help="Exit 1 if any finding meets this severity")
    args = parser.parse_args()
    scanners = list(dict.fromkeys(args.scanners))
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    project = args.project.resolve()
    output = args.output.resolve() if args.output else project / "reports"
    output.mkdir(parents=True, exist_ok=True)
    raw = output / "raw"
    raw.mkdir(exist_ok=True)
    metadata_file = raw / "scan-metadata.json"
    if args.parse_only:
        metadata = json.loads(metadata_file.read_text()) if metadata_file.exists() else {}
    else:
        with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
            futures = {name: executor.submit(run_scanner, name, project, raw, args.timeout)
                       for name in scanners}
            metadata = {name: future.result() for name, future in futures.items()}
        metadata_file.write_text(json.dumps(metadata, indent=2) + "\n")
    report = build_report(project, output, metadata, scanners)
    save_report(report, output)
    for name, scan in report["scans"].items():
        if scan["status"] == "error":
            print(f"{name}: ERROR: {scan['error']}", file=sys.stderr)
        else:
            print(f"{name}: {scan['unique_advisories']} unique advisories; "
                  f"{scan['high_critical_unique_advisories']} high/critical")
    print(f"Reports: {output / 'vulnerabilities.json'}, {output / 'vulnerabilities.csv'}, "
          f"{output / 'vulnerabilities-dedup.csv'}")
    if any(s["status"] == "error" for s in report["scans"].values()):
        return 2
    if args.fail_on and any(SEVERITIES[r["severity"]] >= SEVERITIES[args.fail_on]
                            for r in report["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
