# Dependency audit

**51 merged advisory groups; 0 with no fix reported; 0 with unknown fix availability.**

## Unresolved findings without a reported fix

None in the completed scans.

“No fix reported” means no scanner reported an available fix or patched version; it does not prove that no fix exists. Review affected parent dependencies or replacement packages.

## Scan results

| Scanner | Status | Advisories | High/critical | No fix reported |
| --- | --- | --- | --- | --- |
| npm | completed | 46 | 25 | 0 |
| yarn | completed | 46 | 25 | 0 |
| snyk | completed | 51 | 25 | 0 |

## Priority packages

| Package | Installed versions | High/critical groups | Scanner suggestions |
| --- | --- | --- | --- |
| async | 2.6.0 | 1 | Upgrade mongoose to 9.11.1 \(major version change\) |
| bson | 1.0.9 | 1 | Upgrade mongoose to 9.11.1 \(major version change\) |
| debug | 2.6.1 | 1 | Upgrade express to 4.22.3 |
| fresh | 0.5.0 | 1 | Upgrade express to 4.22.3 |
| jsonwebtoken | 8.1.0 | 1 | Upgrade jsonwebtoken to 9.0.3 \(major version change\) |
| lodash | 4.17.10 | 7 | Upgrade lodash to 4.18.1 |
| mime | 1.3.4 | 1 | Upgrade express to 4.22.3 |
| minimist | 0.0.8 | 1 | Upgrade mocha to 12.0.3 \(major version change\) |
| mocha | 5.0.5 | 2 | Upgrade path: mocha@10.1.0; Upgrade path: mocha@6.0.0 |
| mongodb | 2.2.34 | 1 | Upgrade mongoose to 9.11.1 \(major version change\) |
| mongoose | 4.13.21 | 6 | Upgrade mongoose to 9.11.1 \(major version change\) |
| mquery | 2.3.3 | 2 | Upgrade mongoose to 9.11.1 \(major version change\) |
| path-to-regexp | 0.1.7 | 2 | Upgrade express to 4.22.3 |
| proxy-addr | 1.1.5 | 1 | Upgrade express to 4.22.3 |
| qs | 6.3.1 | 3 | Upgrade express to 4.22.3 |

Counts overlap across scanners. Shared GHSA/CVE IDs or advisory URLs merge findings; the highest source severity is retained. `moderate` is normalized to `medium`.

## Dependency versions

| Package | Declared | Installed |
| --- | --- | --- |
| body-parser | ^1.19.0 | 1.20.8 |
| dotenv | ^8.2.0 | 8.6.0 |
| express | 4.15.0 | 4.15.0 |
| jsonwebtoken | 8.1.0 | 8.1.0 |
| lodash | 4.17.10 | 4.17.10 |
| mongoose | ^4.2.4 | 4.13.21 |
| mocha | 5.0.5 | 5.0.5 |

Installed versions come from saved lockfile snapshots; missing versions are unavailable.

## Evidence and limits

Baseline snapshot: 2026-10-07T21:26:08.422566+00:00.

Baseline evidence: [JSON](vulnerabilities.json), [CSV](vulnerabilities.csv), [merged CSV](vulnerabilities-dedup.csv), [raw scans and metadata](raw).

JSON and CSV retain all advisory IDs, titles, paths, severities, and fix suggestions; raw metadata retains commands, versions, times, and exit codes. A reported fix can apply to only some dependency paths. Clean scans do not establish application compatibility; test major upgrades and rescan the chosen lockfile.
