# Dependency vulnerability assessment

Assessment date: **7 October 2026** (Europe/Madrid). Baseline scans started at **21:59:58 CEST**; candidate scans started at **22:00:58 CEST**. Machine-readable timestamps use UTC. This is a scan of known dependency vulnerabilities, including development and transitive dependencies; application code and exploit reachability were not supplied.

## Results and count definitions

| Scanner | Version | Raw result | Unique advisories | High | Critical | Unique high/critical | Verified candidate |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| npm audit | 11.19.0 | 24 vulnerable packages: 3 low, 3 medium, 8 high, 10 critical; exit 1 | 46 | 18 | 7 | 25 | 0 findings; exit 0 |
| yarn audit | 1.22.22 (Classic) | 68 advisory/path occurrences: 9 low, 23 medium, 27 high, 9 critical; exit 30 | 46 | 18 | 7 | 25 | 0 findings; exit 0 |
| snyk test | 1.1307.4 | 74 vulnerable dependency paths; exit 1 | 51 | 24 | 1 | 25 | 0 findings; exit 0 |

npm's package counts include inherited vulnerabilities: for example, Express and Mocha receive critical package ratings because their dependencies are critical. Those are not additional critical advisories against Express or Mocha themselves. npm/Yarn's 46 unique advisories comprise 6 low, 15 medium, 18 high, and 7 critical. Snyk's 51 comprise 6 low, 20 medium, 24 high, and 1 critical; the Python report keeps `medium` and normalizes npm/Yarn's `moderate` to `medium`.

Do not sum scanner totals. npm and Yarn returned the same 46 advisory IDs. Repeated dependency paths are aggregated per scanner/package/advisory in the exported reports. Snyk uses different IDs, coverage and severity assessments; its 25 priority findings are not identical to npm/Yarn's 25. The source-specific tables below preserve these differences.

Raw outputs and exact commands/versions/exits are in [reports/raw/](reports/raw/) and [scan-metadata.json](reports/raw/scan-metadata.json). Full findings at every severity are in [JSON](reports/vulnerabilities.json) and [CSV](reports/vulnerabilities.csv).

## Declared versus resolved dependencies

No lockfile was supplied. Lockfiles were generated on the assessment date with lifecycle scripts disabled. Caret ranges do not mean the lower-bound version is installed; the resolved versions below are the actual baseline scanned. This assessment cannot reconstruct a historical production installation.

| Direct dependency | Declared version | Resolved baseline | Recommended, verified resolution | Action |
| --- | --- | --- | --- | --- |
| body-parser | ^1.19.0 | 1.20.8 | 1.20.8 | Retain resolved patch; no advisory returned against this version |
| dotenv | ^8.2.0 | 8.6.0 | 8.6.0 | No advisory returned against this version |
| express | 4.15.0 | 4.15.0 | **4.22.3** | Update within major 4, including its vulnerable HTTP dependencies |
| lodash | 4.17.10 | 4.17.10 | **4.18.1** | Update direct copy; update Mongoose to remove its old transitive copy |
| jsonwebtoken | 8.1.0 | 8.1.0 | **9.0.3** | Major upgrade; review JWT verification behavior |
| mongoose | ^4.2.4 | 4.13.21 | **9.11.1** | Major migration; replaces vulnerable MongoDB driver, BSON, mquery, async, and lodash paths |
| mocha (development) | 5.0.5 | 5.0.5 | **12.0.3** | Major upgrade; removes vulnerable mkdirp/minimist and fixes Mocha ReDoS |

The proposed [manifest](remediation/package.json) changes five direct dependencies and retains the original body-parser/dotenv ranges. Its [npm lockfile](remediation/package-lock.json) and [Yarn lockfile](remediation/yarn.lock) record the tested resolutions. Original `package.json` is unchanged.

## High/critical advisories from npm and Yarn

Each row is one unique advisory, not one dependency path. Patched ranges are advisory-specific minimums returned by Yarn; use the combined direct-dependency upgrade plan above to address all advisories together. In particular, a fix for an older advisory may still be vulnerable to newer advisories.

| Severity | Vulnerable dependency and resolved version | Vulnerability / advisory | Advisory patched range |
| --- | --- | --- | --- |
| critical | bson 1.0.9 | Deserialization of Untrusted Data in bson ([GHSA-v8w9-2789-6hhr](https://github.com/advisories/GHSA-v8w9-2789-6hhr)) | >=1.1.4 |
| critical | lodash 4.17.10 | Prototype Pollution in lodash ([GHSA-jf85-cpcp-j695](https://github.com/advisories/GHSA-jf85-cpcp-j695)) | >=4.17.12 |
| critical | minimist 0.0.8 | Prototype Pollution in minimist ([GHSA-xvch-5gv4-984h](https://github.com/advisories/GHSA-xvch-5gv4-984h)) | >=0.2.4 |
| critical | mongoose 4.13.21 | Mongoose Prototype Pollution vulnerability ([GHSA-9m93-w8w6-76hh](https://github.com/advisories/GHSA-9m93-w8w6-76hh)) | >=5.13.20 |
| critical | mongoose 4.13.21 | Mongoose Vulnerable to Prototype Pollution in Schema Object ([GHSA-h8hf-x3f4-xwgp](https://github.com/advisories/GHSA-h8hf-x3f4-xwgp)) | >=5.13.15 |
| critical | mongoose 4.13.21 | Mongoose search injection vulnerability ([GHSA-vg7j-7cwx-8wgw](https://github.com/advisories/GHSA-vg7j-7cwx-8wgw)) | >=6.13.6 |
| critical | proxy-addr 1.1.5 | proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet ([GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h)) | >=2.0.8 |
| high | async 2.6.0 | Prototype Pollution in async ([GHSA-fwr7-v2mv-hh25](https://github.com/advisories/GHSA-fwr7-v2mv-hh25)) | >=2.6.4 |
| high | debug 2.6.1 | debug Inefficient Regular Expression Complexity vulnerability ([GHSA-9vvw-cc9w-f27h](https://github.com/advisories/GHSA-9vvw-cc9w-f27h)) | >=2.6.9 |
| high | fresh 0.5.0 | Regular Expression Denial of Service in fresh ([GHSA-9qj9-36jm-prpv](https://github.com/advisories/GHSA-9qj9-36jm-prpv)) | >=0.5.2 |
| high | jsonwebtoken 8.1.0 | jsonwebtoken unrestricted key type could lead to legacy keys usage ([GHSA-8cf7-32gw-wr33](https://github.com/advisories/GHSA-8cf7-32gw-wr33)) | >=9.0.0 |
| high | lodash 4.17.10 | Command Injection in lodash ([GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm)) | >=4.17.21 |
| high | lodash 4.17.10 | Prototype Pollution in lodash ([GHSA-4xc9-xhrj-v574](https://github.com/advisories/GHSA-4xc9-xhrj-v574)) | >=4.17.11 |
| high | lodash 4.17.10 | Prototype Pollution in lodash ([GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw)) | >=4.17.19 |
| high | lodash 4.17.10 | lodash vulnerable to Code Injection via `_.template` imports key names ([GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc)) | >=4.18.0 |
| high | mime 1.3.4 | mime Regular Expression Denial of Service when MIME lookup performed on untrusted user input ([GHSA-wrvr-8mpx-r7pp](https://github.com/advisories/GHSA-wrvr-8mpx-r7pp)) | >=1.4.1 |
| high | mongodb 2.2.34 | Denial of Service in mongodb ([GHSA-mh5c-679w-hh4r](https://github.com/advisories/GHSA-mh5c-679w-hh4r)) | >=3.1.13 |
| high | mongoose 4.13.21 | automattic/mongoose vulnerable to Prototype pollution via Schema.path ([GHSA-f825-f98c-gj3g](https://github.com/advisories/GHSA-f825-f98c-gj3g)) | >=5.13.15 |
| high | mongoose 4.13.21 | Mongoose search injection vulnerability ([GHSA-m7xq-9374-9rvx](https://github.com/advisories/GHSA-m7xq-9374-9rvx)) | >=5.13.23 |
| high | mongoose 4.13.21 | Mongoose's Improper Sanitization of $nor in sanitizeFilter May Allow NoSQL Injection ([GHSA-wpg9-53fq-2r8h](https://github.com/advisories/GHSA-wpg9-53fq-2r8h)) | >=6.13.9 |
| high | path-to-regexp 0.1.7 | path-to-regexp vulnerable to Regular Expression Denial of Service via multiple route parameters ([GHSA-37ch-88jc-xwx2](https://github.com/advisories/GHSA-37ch-88jc-xwx2)) | >=0.1.13 |
| high | path-to-regexp 0.1.7 | path-to-regexp outputs backtracking regular expressions ([GHSA-9wv6-86v2-598j](https://github.com/advisories/GHSA-9wv6-86v2-598j)) | >=0.1.10 |
| high | path-to-regexp 0.1.7 | path-to-regexp contains a ReDoS ([GHSA-rhx6-c78j-4q9w](https://github.com/advisories/GHSA-rhx6-c78j-4q9w)) | >=0.1.12 |
| high | qs 6.3.1 | Prototype Pollution Protection Bypass in qs ([GHSA-gqgv-6jq5-jjj9](https://github.com/advisories/GHSA-gqgv-6jq5-jjj9)) | >=6.3.2 |
| high | qs 6.3.1 | qs vulnerable to Prototype Pollution ([GHSA-hrpp-h998-j3pp](https://github.com/advisories/GHSA-hrpp-h998-j3pp)) | >=6.3.3 |

These findings are reachable through the following dependency relationships (all paths are recorded in the exports):

| Direct upgrade | Vulnerable packages it addresses |
| --- | --- |
| express 4.22.3 | express → proxy-addr, qs, path-to-regexp, debug, fresh; express → send/serve-static → mime, debug, fresh; also lower-severity cookie/ms/send/serve-static findings |
| lodash 4.18.1 | Direct lodash copy |
| jsonwebtoken 9.0.3 | jsonwebtoken key-type handling and lower-severity algorithm/key verification findings |
| mongoose 9.11.1 | mongoose; mongoose → async → lodash; mongoose → mquery; mongoose → mongodb → mongodb-core → bson; mongoose → bson; also mpath |
| mocha 12.0.3 | mocha; mocha → mkdirp → minimist; also diff |

The historical recommendation “lodash 4.17.21” fixes several older findings, but is insufficient for this scan. The [2026 template imports code-injection advisory](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) marks versions through 4.17.23 as affected and 4.18.0 as patched; [Snyk recommends 4.18.1 for that advisory](https://security.snyk.io/vuln/SNYK-JS-LODASH-15869625). **4.18.1** was verified with all tools.

## High/critical advisories from Snyk

These are Snyk's 25 unique priority advisories; shared issues appear in both source-specific tables intentionally. Fixed versions are source-provided branches, not a recommendation to stay on obsolete major versions. Use the verified direct upgrades above.

| Severity | Vulnerable dependency and resolved version | Vulnerability / Snyk advisory | Source-provided fixed versions |
| --- | --- | --- | --- |
| critical | proxy-addr 1.1.5 | User Impersonation ([SNYK-JS-PROXYADDR-19812342](https://security.snyk.io/vuln/SNYK-JS-PROXYADDR-19812342)) | 2.0.8 |
| high | async 2.6.0 | Prototype Pollution ([SNYK-JS-ASYNC-2441827](https://security.snyk.io/vuln/SNYK-JS-ASYNC-2441827)) | 2.6.4, 3.2.2 |
| high | bson 1.0.9 | Internal Property Tampering ([SNYK-JS-BSON-561052](https://security.snyk.io/vuln/SNYK-JS-BSON-561052)) | 1.1.4 |
| high | bson 1.0.9 | Internal Property Tampering ([SNYK-JS-BSON-6056525](https://security.snyk.io/vuln/SNYK-JS-BSON-6056525)) | 1.1.4 |
| high | fresh 0.5.0 | Regular Expression Denial of Service (ReDoS) ([npm:fresh:20170908](https://security.snyk.io/vuln/npm:fresh:20170908)) | 0.5.2 |
| high | lodash 4.17.10 | Code Injection ([SNYK-JS-LODASH-1040724](https://security.snyk.io/vuln/SNYK-JS-LODASH-1040724)) | 4.17.21 |
| high | lodash 4.17.10 | Arbitrary Code Injection ([SNYK-JS-LODASH-15869625](https://security.snyk.io/vuln/SNYK-JS-LODASH-15869625)) | 4.18.1 |
| high | lodash 4.17.10 | Prototype Pollution ([SNYK-JS-LODASH-450202](https://security.snyk.io/vuln/SNYK-JS-LODASH-450202)) | 4.17.12 |
| high | lodash 4.17.10 | Prototype Pollution ([SNYK-JS-LODASH-567746](https://security.snyk.io/vuln/SNYK-JS-LODASH-567746)) | 4.17.20 |
| high | lodash 4.17.10 | Prototype Pollution ([SNYK-JS-LODASH-608086](https://security.snyk.io/vuln/SNYK-JS-LODASH-608086)) | 4.17.17 |
| high | lodash 4.17.10 | Prototype Pollution ([SNYK-JS-LODASH-6139239](https://security.snyk.io/vuln/SNYK-JS-LODASH-6139239)) | 4.17.17 |
| high | lodash 4.17.10 | Prototype Pollution ([SNYK-JS-LODASH-73638](https://security.snyk.io/vuln/SNYK-JS-LODASH-73638)) | 4.17.11 |
| high | mocha 5.0.5 | Regular Expression Denial of Service (ReDoS) ([SNYK-JS-MOCHA-2863123](https://security.snyk.io/vuln/SNYK-JS-MOCHA-2863123)) | 10.1.0 |
| high | mocha 5.0.5 | Regular Expression Denial of Service (ReDoS) ([SNYK-JS-MOCHA-561476](https://security.snyk.io/vuln/SNYK-JS-MOCHA-561476)) | 6.0.0 |
| high | mongodb 2.2.34 | Denial of Service (DoS) ([SNYK-JS-MONGODB-473855](https://security.snyk.io/vuln/SNYK-JS-MONGODB-473855)) | 3.1.13 |
| high | mongoose 4.13.21 | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') ([SNYK-JS-MONGOOSE-16425765](https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-16425765)) | 6.13.9, 7.8.9, 8.22.1, 9.1.6 |
| high | mongoose 4.13.21 | Prototype Pollution ([SNYK-JS-MONGOOSE-2961688](https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-2961688)) | 5.13.15, 6.4.6 |
| high | mongoose 4.13.21 | Prototype Pollution ([SNYK-JS-MONGOOSE-5777721](https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-5777721)) | 5.13.20, 6.11.3, 7.3.4 |
| high | mongoose 4.13.21 | Improper Neutralization of Special Elements in Data Query Logic ([SNYK-JS-MONGOOSE-8446504](https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-8446504)) | 6.13.5, 7.8.3, 8.8.3 |
| high | mongoose 4.13.21 | Improper Neutralization of Special Elements in Data Query Logic ([SNYK-JS-MONGOOSE-8623536](https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-8623536)) | 6.13.6, 7.8.4, 8.9.5 |
| high | mquery 2.3.3 | Prototype Pollution ([SNYK-JS-MQUERY-1050858](https://security.snyk.io/vuln/SNYK-JS-MQUERY-1050858)) | 3.2.3 |
| high | mquery 2.3.3 | Prototype Pollution ([SNYK-JS-MQUERY-1089718](https://security.snyk.io/vuln/SNYK-JS-MQUERY-1089718)) | 3.2.5 |
| high | qs 6.3.1 | Allocation of Resources Without Limits or Throttling ([SNYK-JS-QS-14724253](https://security.snyk.io/vuln/SNYK-JS-QS-14724253)) | 6.14.1 |
| high | qs 6.3.1 | Prototype Poisoning ([SNYK-JS-QS-3153490](https://security.snyk.io/vuln/SNYK-JS-QS-3153490)) | 6.10.3, 6.2.4, 6.3.3, 6.4.1, 6.5.3, 6.6.1, 6.7.3, 6.8.3, 6.9.7 |
| high | qs 6.3.1 | Prototype Override Protection Bypass ([npm:qs:20170213](https://security.snyk.io/vuln/npm:qs:20170213)) | 6.0.4, 6.1.2, 6.2.3, 6.3.2 |

Snyk additionally reports two Mocha ReDoS advisories, mquery's `mergeClone()` prototype pollution, and two Lodash prototype-pollution advisories without CVEs that do not appear in npm/Yarn's advisory set. It rates `mquery` CVE-2020-35149, `bson` CVE-2019-2391 and `qs` CVE-2025-15284 high, while npm/Yarn rate those medium. npm/Yarn rate some shared prototype-pollution issues critical while Snyk rates them high. These severity differences do not change the upgrade plan.

## Remediation and how many issues can be fixed

All priority findings have upgrade paths. Applying the five direct upgrades to the isolated candidate cleared:

| Scanner | Unique advisories cleared | High/critical cleared | Additional count cleared | Remaining |
| --- | ---: | ---: | --- | ---: |
| npm | **46/46** | **25/25** | All 24 vulnerable-package entries | **0** |
| Yarn | **46/46** | **25/25** | All 68 advisory/path occurrences | **0** |
| Snyk | **51/51** | **25/25** | All 74 vulnerable dependency paths | **0** |

These are overlapping source-specific counts, not 143 distinct vulnerabilities. See [the before/after ID comparison](reports/remediation-comparison.json) and [candidate scan evidence](remediation/reports/vulnerabilities.json). The candidate produced no new findings in any scanner.

npm marks remediation available for all 24 affected packages. Yarn reports patched ranges for all 46 advisories. Snyk offers an upgrade for at least one path of each of its 51 advisories, but only 63 of its 74 vulnerable path occurrences have `isUpgradable=true`. A single package's suggested upgrade may leave other paths behind: the full parent-dependency plan was needed and verified. Available scanner fixes do not by themselves prove application compatibility.

Apply the proposed versions in the real application and regenerate its chosen lockfile. Both lock formats are retained here for the requested assessment; standardize on one package manager and lockfile for production. Review `npm audit fix --dry-run` before using automatic remediation; avoid applying `npm audit fix --force` without reviewing the major upgrades it selects. [npm audit documentation](https://docs.npmjs.com/cli/v11/commands/npm-audit/)

The candidate was installed with `--ignore-scripts` and tested using Node.js **24.21.0**. Mongoose 9.11.1 requires Node >=20.19.0; Mocha 12.0.3 requires ^20.19.0 or >=22.12.0 according to the resolved package metadata. Move the deployed runtime to a compatible maintained release if necessary. Application tests were unavailable: the provided input was only a manifest. Database, JWT and test-runner migrations remain application integration work.

Use the [Mongoose migration guides](https://mongoosejs.com/docs/migrating_to_9.html) for the intervening majors, checking callbacks/promises, query/filter behavior, middleware, and MongoDB server compatibility. The [jsonwebtoken 8→9 migration notes](https://github.com/auth0/node-jsonwebtoken/wiki/Migration-Notes%3A-v8-to-v9) describe stricter key and algorithm requirements. Test valid and invalid tokens, explicitly allowlist expected algorithms, and preserve issuer/audience checks. Check Mocha test discovery and CLI changes after its major upgrade.

Until integration is complete, reject unexpected object keys and validate request/query shapes before database operations or object merges; keep untrusted input out of Lodash template compilation and schema definitions. Limit request size and processing time to reduce ReDoS/DoS exposure. Review Express `trust proxy` and forwarded-header assumptions because of the critical proxy-addr spoofing advisory. These measures reduce exposure and do not replace upgrading affected dependencies. Keep development dependencies out of production installations (`npm ci --omit=dev`); still scan and upgrade the CI/test environment.

## Reproduction and automated reporting

[generate_audit_report.py](generate_audit_report.py) produces concise summaries from saved JSON. See the [baseline summary](reports/AUDIT_REPORT.md), [remediation comparison](reports/REMEDIATION_COMPARISON.md), and [README](README.md) for usage. The comparison prioritizes remaining findings and fix availability. These generated reports are separate from the reviewed migration recommendations in this document.

Run from `04-dependency-audit`:

```sh
npm ci --ignore-scripts --no-audit --no-fund --cache .scan/npm-cache
python3 audit_dependencies.py --scanners npm yarn snyk --fail-on high
```

The script invokes exactly:

```sh
npm audit --json --cache .scan/npm-cache
yarn audit --json --registry https://registry.npmjs.org
snyk test --file=package.json --package-manager=npm --dev --json
```

Snyk needs installed `node_modules` for this project, so `npm ci` is a prerequisite. Yarn Classic supports JSON lines; its exit 30 means severity bits 2+4+8+16 (low/moderate/high/critical), rather than a scanner execution failure. [Yarn audit documentation](https://classic.yarnpkg.com/lang/en/docs/cli/audit/) Snyk exit 1 means findings and exit 2 means execution failure. [Snyk test documentation](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)

The Python script uses only the standard library. It runs the scanners concurrently, preserves raw stdout/stderr, commands, tool versions, timestamps and exit codes, then exports normalized JSON/CSV, including a separate CSV deduplicated across scanners by shared advisory identifiers. It deduplicates repeated paths per scanner/package/advisory, captures versions and patched versions/remediation, reports authentication/network/timeout/parsing failures as errors, and protects CSV cells from spreadsheet formulas. It never treats a failed scan as a clean result. The existing Snyk login/configuration is used; authentication credentials are not copied to reports.

```sh
# Replay existing evidence without network; returns 1 for this vulnerable baseline.
python3 audit_dependencies.py --scanners npm yarn snyk --parse-only --fail-on high

# Verify the proposed dependency graph; returned 0 in this assessment.
npm ci --prefix remediation --ignore-scripts --no-audit --no-fund --cache .scan/npm-cache
python3 audit_dependencies.py --scanners npm yarn snyk --project remediation --fail-on high

# Offline checks for selection, matching, failures, CSV safety and Markdown reporting.
python3 -m unittest -v test_audit_dependencies test_generate_audit_report
```

Commit the application manifest and chosen lockfile, install reproducibly in CI, and gate changes on `python3 audit_dependencies.py --scanners npm yarn snyk --fail-on high` after lockfiles/dependencies are prepared. Repeat scans on a schedule because advisories change. The stored report includes input SHA-256 hashes; scanner metadata preserves actual scan times even when offline report generation is rerun.
