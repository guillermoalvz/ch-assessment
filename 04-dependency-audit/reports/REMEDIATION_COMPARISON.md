# Remediation comparison

**No unresolved findings:** all selected proposal scans completed with zero findings.

## Unresolved findings without a reported fix

None in the completed scans.

“No fix reported” means no scanner reported an available fix or patched version; it does not prove that no fix exists. Review affected parent dependencies or replacement packages.

## Scan results

| Scanner | Baseline advisories | Proposal advisories | No longer reported | Still reported | Newly reported |
| --- | --- | --- | --- | --- | --- |
| npm | 46 | 0 | 46 | 0 | 0 |
| snyk | 51 | 0 | 51 | 0 | 0 |
| yarn | 46 | 0 | 46 | 0 | 0 |

Changes match package/advisory IDs within each scanner. Missing or failed scans cannot establish that a finding was removed.

Counts overlap across scanners. Shared GHSA/CVE IDs or advisory URLs merge findings; the highest source severity is retained. `moderate` is normalized to `medium`.

## Dependency versions

| Package | Installed baseline | Installed proposal |
| --- | --- | --- |
| express | 4.15.0 | 4.22.3 |
| jsonwebtoken | 8.1.0 | 9.0.3 |
| lodash | 4.17.10 | 4.18.1 |
| mongoose | 4.13.21 | 9.11.1 |
| mocha | 5.0.5 | 12.0.3 |

Installed versions come from saved lockfile snapshots; missing versions are unavailable.

## Evidence and limits

Baseline snapshot: 2026-10-07T21:26:08.422566+00:00.

Baseline evidence: [JSON](vulnerabilities.json), [CSV](vulnerabilities.csv), [merged CSV](vulnerabilities-dedup.csv), [raw scans and metadata](raw).

Proposal snapshot: 2026-10-07T21:26:08.880802+00:00.

Proposal evidence: [JSON](../remediation/reports/vulnerabilities.json), [CSV](../remediation/reports/vulnerabilities.csv), [merged CSV](../remediation/reports/vulnerabilities-dedup.csv), [raw scans and metadata](../remediation/reports/raw).

JSON and CSV retain all advisory IDs, titles, paths, severities, and fix suggestions; raw metadata retains commands, versions, times, and exit codes. A reported fix can apply to only some dependency paths. Clean scans do not establish application compatibility; test major upgrades and rescan the chosen lockfile.
