# Dependency security audit

This directory audits the original Node.js dependencies with npm, Yarn Classic, and Snyk, then checks a separate upgrade proposal.

The saved baseline scans report **25 high/critical advisories per scanner**. The saved proposal scans report **zero findings in all three tools** as of 2026-10-08. Scanner results overlap, so do not add their counts together. See [AUDIT_REPORT.md](AUDIT_REPORT.md) for summarized findings and recommendations.

## How remediation works

The proposed fix is in [remediation/package.json](remediation/package.json). It upgrades five direct dependencies:

| Package | Baseline installed version | Proposed version | What it addresses |
| --- | --- | --- | --- |
| Express | 4.15.0 | 4.22.3 | Express and its HTTP dependencies |
| Lodash | 4.17.10 | 4.18.1 | The application's direct Lodash dependency |
| jsonwebtoken | 8.1.0 | 9.0.3 | JWT handling vulnerabilities |
| Mongoose | 4.13.21 | 9.11.1 | Mongoose, MongoDB/BSON dependencies, and an older Lodash copy |
| Mocha | 5.0.5 | 12.0.3 | Mocha and test dependencies such as mkdirp/minimist |

Upgrading parent packages also replaces vulnerable **transitive dependencies**: packages they install indirectly. Updating only the application's Lodash dependency would leave Mongoose's older Lodash copy in place. The body-parser and dotenv version ranges are unchanged.

The proposal has its own npm and Yarn lockfiles, recording the exact versions to install. Keeping it in `remediation/` preserves the original manifest and lets the same scanners compare both dependency graphs.

**The scripts scan and report; they do not automatically upgrade packages.** To apply the proposal to a real application, update its manifest, regenerate its chosen package manager's lockfile, test, and rescan. Mongoose, jsonwebtoken, and Mocha cross major versions and need compatibility checks. Application code was not supplied, so clean scans do not verify application behavior.

## Run and compare

You need Python 3, compatible Node.js/npm, Yarn Classic (1.x), and an authenticated Snyk CLI. The assessment used Node.js 24.21.0. Run these commands from `04-dependency-audit/`.

1. Install and scan the original dependencies. Results go to `reports/`.

   ```sh
   npm ci --ignore-scripts --no-audit --no-fund --cache .scan/npm-cache
   python3 audit_dependencies.py --scanners npm yarn snyk --fail-on high
   ```

2. Install and scan the proposal separately. Results go to `remediation/reports/`.

   ```sh
   npm ci --prefix remediation --ignore-scripts --no-audit --no-fund --cache .scan/npm-cache
   python3 audit_dependencies.py --scanners npm yarn snyk --project remediation --fail-on high
   ```

3. Generate the baseline summary and remediation comparison. Both go to `reports/`.

   ```sh
   python3 generate_audit_report.py
   python3 generate_audit_report.py \
     --comparison remediation/reports/vulnerabilities.json
   ```

The audit includes development dependencies and all severity levels. With `--fail-on high`, exit **0** means all selected scanners completed with no high/critical findings, **1** means those findings exist, and **2** means a scanner failed. Failed scans cannot establish that an issue was fixed. The Markdown generator compares saved results without running scanners.

## Reports and other options

| Location | Contents |
| --- | --- |
| [AUDIT_REPORT.md](AUDIT_REPORT.md) | Reviewed findings, upgrade rationale, and migration advice |
| [reports/AUDIT_REPORT.md](reports/AUDIT_REPORT.md) | Generated baseline summary |
| [reports/REMEDIATION_COMPARISON.md](reports/REMEDIATION_COMPARISON.md) | Remaining findings first, especially those without a reported fix; then before/after counts |
| [reports/](reports/) | JSON findings and scanner status, plus CSV exports |
| [reports/raw/](reports/raw/) | Original scanner output, commands, versions, and exit codes |
| [remediation/reports/](remediation/reports/) | Equivalent reports for the proposal |

`vulnerabilities.csv` combines repeated paths per scanner/package/advisory. `vulnerabilities-dedup.csv` also merges findings across scanners using shared GHSA/CVE IDs or advisory URLs. Normalized reports use `medium` for npm/Yarn's `moderate` severity.

Generated Markdown defaults to the input JSON's directory: `AUDIT_REPORT.md` for a baseline and `REMEDIATION_COMPARISON.md` with `--comparison`. Use the generator's `--output PATH` to override this. The root `AUDIT_REPORT.md` is the separately reviewed assessment. “No fix reported” and unknown fix availability are shown separately; neither is treated as a patched finding.

`--scanners` is required; list only the tools you want to run. `--output PATH` preserves a run in a separate directory; otherwise reports are overwritten. `--parse-only` rebuilds exports from saved raw output without network access. Keep manifests and lockfiles aligned with that evidence. Both Python scripts provide `--help`.

Run the existing offline tests with:

```sh
python3 -m unittest -v test_audit_dependencies test_generate_audit_report
```
