# unisupply

> Go supply chain assessment — one letter grade from vulnerabilities and project upkeep, typosquatting, CI/CD audit, SBOM, policy enforcement.

[![CI](https://github.com/unidoc/unisupply/actions/workflows/ci.yml/badge.svg)](https://github.com/unidoc/unisupply/actions/workflows/ci.yml)
[![Release](https://github.com/unidoc/unisupply/actions/workflows/release.yml/badge.svg)](https://github.com/unidoc/unisupply/actions/workflows/release.yml)
[![CodeQL](https://github.com/unidoc/unisupply/actions/workflows/codeql.yml/badge.svg)](https://github.com/unidoc/unisupply/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/unidoc/unisupply)](https://goreportcard.com/report/github.com/unidoc/unisupply)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## What it does

`unisupply` analyzes a Go project's full module dependency chain and produces a
supply chain assessment. It runs nine focused scanners — vulnerability
lookup, maintenance health, maintainer analysis, typosquatting detection,
resilience scoring, CI/CD pipeline audit, build
file inspection, `go.mod`/`go.sum` integrity audit (replace/exclude
directives, go.sum completeness, go.sum verification), and Trust Index
lookup — grades the module and each dependency from the in-tree scanner signals
into one letter, A to F, with the row that decided it, attaches the optional
Trust Index data to each report, and renders the result as a colored terminal
summary, machine-readable JSON, an enterprise PDF report, or a CycloneDX /
SPDX SBOM. A built-in policy engine fails CI on configurable thresholds
(critical vulns, max age, blocked modules, unpinned actions, ...).

It is intended for engineering teams that need to make merge-time and
release-time decisions about third-party Go code.

## Install

```bash
# Latest release (Go 1.26+ required)
go install github.com/unidoc/unisupply/cmd/unisupply@latest

# Pinned version (recommended for reproducible environments)
go install github.com/unidoc/unisupply/cmd/unisupply@v0.6.0

# Or download a prebuilt binary from the Releases page
#   https://github.com/unidoc/unisupply/releases
```

Homebrew and other package-manager distribution channels are tracked as
post-1.0 follow-ups; for now use `go install` or the release tarballs.

## Quick start

```bash
# Scan the current module
unisupply ./

# JSON output for CI ingestion
unisupply ./ --format json --output results.json

# Full PDF report (requires UNIDOC_LICENSE_API_KEY for PDF generation)
unisupply ./ \
    --format pdf \
    --output report.pdf \
    --github-token "$GITHUB_TOKEN"

# Policy-enforced run — exits 2 on violation
unisupply ./ --policy-preset strict
```

A text-format run reports the grade first, then the rows behind it. This is the
real output (truncated: the dependency has two more findings, and your output
lists every row that needs attention, `--verbose` all of them) for a small
module that imports `gopkg.in/yaml.v2 v2.2.2` and calls `yaml.Unmarshal`:

```
SUPPLY-CHAIN GRADE: D
  Decided by: gopkg.in/yaml.v2 (score 70) — called high GO-2022-0956 (70)

GRADE TABLE (worst first)
  MODULE                         VERSION                             GRADE  SCORE  UPKEEP      REASON
  gopkg.in/yaml.v2               v2.2.2                              D         70  unknown     called high GO-2022-0956 (70)
      GO-2022-0956  severity HIGH, tier called, counted
        Fixed in: v2.2.4
        Response: Fix available for 1506 days; the graded version still requires the affected gopkg.in/yaml.v2 version.
        History: Not enough response history.
        VEX: affected
        Condition: reached through gopkg.in/yaml.v2.Unmarshal
  example.com/app (this module)                                      A          0  finished    nothing found
  gopkg.in/check.v1              v0.0.0-20161208181325-20d25e280405  A          0  unknown     upkeep could not be read

GRADE NOTES
  - The known-exploited status (CISA's catalog) could not be checked for 3 reached findings: one on that list would grade F.
  - The module's own advisories were not looked up: no module version was given.
```

The SCORE column holds the policy values the letter is picked from. They are
shown so you can follow the arithmetic; they are not a measurement and not a
risk score (see [docs/grading.md](docs/grading.md)).

An offline run (`unisupply ./ --offline --module-version v1.0.0`, captured from
the built CLI on a one-dependency module) cannot check for vulnerabilities, so
the grade is Pending and says why:

```
SUPPLY-CHAIN GRADE: PENDING
  Why: the vulnerability scan did not run: offline — vulnerability scan skipped (no local vuln DB mirror configured)
  Check that did not run: vulnerability_scan

GRADE TABLE (worst first)
  MODULE                            VERSION  GRADE  SCORE  UPKEEP      REASON
  example.com/sample (this module)  v1.0.0   -          0  unknown     upkeep could not be read
  gopkg.in/ini.v1                   v1.67.0  -          0  unknown     upkeep could not be read

SCAN LIMITATIONS — the results above are incomplete
  ! offline — maintenance data unavailable for 1 module(s)
  ! vulnerability scan did not run
```

A row whose upkeep could not be read has no letter (`-`).

Pass `--verbose` for full per-dependency breakdowns including the dependency
path that pulled the module in.

## Scanners

| Scanner          | What it checks                                          | Data source                |
| ---------------- | ------------------------------------------------------- | -------------------------- |
| Vulnerability    | Known CVEs in dependencies                              | Go vuln DB (vuln.go.dev)   |
| Maintenance      | Last release, default-branch activity, archive status, deprecation (incl. go.mod `// Deprecated:`), retraction | Go Module Proxy (GitHub commits API as a fallback) |
| Maintainer       | Contributors, bus factor, activity, org verification    | GitHub API                 |
| Typosquatting    | Levenshtein-similarity to ~75 well-known modules        | Built-in list              |
| Resilience       | Release cadence, governance files, version scheme       | GitHub API                 |
| CI/CD            | Action pinning, permissions, secret exposure            | `.github/workflows/*.yml`  |
| Build files      | Unpinned Docker images, `curl \| bash` patterns         | Dockerfile, Makefile, *.sh |
| Integrity        | `go.mod` `replace`/`exclude` directive audit            | `go.mod` (offline)         |
| Trust Index      | Curated trust scores                                    | unitrust API (optional)    |

**The grade.** `unisupply` publishes one letter, A to F, with the evidence behind it. The module itself and every
dependency get one score (the higher of its vulnerability score and its upkeep score); the letter comes from the worst
row, and the report names that row and says why. D and F mean a confirmed problem: a known vulnerability in code that is
reached, or a checksum that does not match. Archived or deprecated projects count, but only up to C. Vulnerable code that
is never compiled is shown, not graded. When a check the grade needs did not run, the grade is **Pending** and has no
letter. A means nothing crossed a scoring threshold in this assessment; it does not certify that the project is secure.
The full rules are in [docs/grading.md](docs/grading.md).

**Build membership.** A module can be in your dependency graph without being
compiled into your binary (it is required by a dependency's `go.mod` but none
of its packages is imported). `unisupply` classifies each module against the
main module's own `go list -deps ./...` and `go list -deps -test ./...` for
linux, darwin and windows on amd64 and arm64, and reports `in_build` (`false`: graph only),
`test_only` and `platforms` (the GOOS values of a platform-specific module) in
the JSON output; the text and PDF reports label such modules `outside build` or
`test-only`. An unknown classification is omitted and never discounts. When the
vulnerability scan found nothing reachable and the grade is decided by
dependency health alone, the grade says so. See
[docs/scanners.md](docs/scanners.md#build-membership) for the rules, limits and
which signals honour build membership.


## Output formats

| Format                | Flag                       | Use                                                 |
| --------------------- | -------------------------- | --------------------------------------------------- |
| Text (colored)        | `--format text` (default)  | Interactive terminal use                            |
| JSON                  | `--format json`            | CI ingestion, dashboards, programmatic consumers    |
| PDF                   | `--format pdf`             | Enterprise reports (built with UniPDF + UniChart)   |
| CycloneDX SBOM        | `--format sbom-cyclonedx`  | Standard CycloneDX 1.5 software bill of materials   |
| SPDX SBOM             | `--format sbom-spdx`       | SPDX 2.3 software bill of materials                 |

The JSON output includes per-CVE reachability information. Each vulnerability
entry carries a `reachability` field (`"called"`, `"imported"`, or
`"required"`) that reflects how deeply the vulnerable symbol is reachable in
your build's call graph — see
[docs/scanners.md § Vulnerability reachability](docs/scanners.md#vulnerability-reachability)
for the exact definitions and scoring effect.

Each CVE also carries threat-intel enrichment: `epss_score` /
`epss_percentile` (FIRST.org's exploitation-probability prediction) and
`in_kev` (presence in CISA's Known Exploited Vulnerabilities catalog). Both
are shown as data, and a called finding on the KEV list grades F — see
[docs/grading.md](docs/grading.md).

```json
{
  "module": "golang.org/x/net",
  "version": "v0.35.0",
  "vulnerabilities": [
    {
      "id": "GO-2025-0001",
      "aliases": ["CVE-2025-12345"],
      "summary": "HTTP/2 request smuggling in golang.org/x/net/http2",
      "severity": "HIGH",
      "fixed_version": "v0.36.0",
      "reachability": "called",
      "call_path": [
        "example.com/app/cmd/app.main",
        "golang.org/x/net/http2.Server.ServeConn"
      ],
      "call_trace": [
        {
          "name": "example.com/app/cmd/app.main",
          "module": "example.com/app",
          "file": "cmd/app/main.go",
          "line": 42,
          "column": 18,
          "project": true
        },
        {
          "name": "golang.org/x/net/http2.Server.ServeConn",
          "module": "golang.org/x/net",
          "version": "v0.35.0",
          "file": "http2/server.go",
          "line": 412,
          "column": 22
        }
      ],
      "called_symbols": ["golang.org/x/net/http2.Server.ServeConn"],
      "epss_score": 0.89,
      "epss_percentile": 0.994,
      "epss_date": "2026-07-10",
      "in_kev": true,
      "kev_date_added": "2026-07-01",
      "kev_known_ransomware": "Unknown"
    },
    {
      "id": "GO-2025-0002",
      "aliases": ["CVE-2025-67890"],
      "summary": "DoS in unused websocket handler",
      "severity": "MEDIUM",
      "fixed_version": "v0.36.0",
      "reachability": "imported",
      "epss_score": 0.004,
      "epss_percentile": 0.31,
      "epss_date": "2026-07-10",
      "in_kev": false
    }
  ]
}
```

Absent `reachability` on a non-govulncheck finding is treated as `"called"`.

Vulnerabilities in the Go standard library of the project's toolchain are not
attached to a dependency. They appear in a top-level `stdlib_vulnerabilities`
array after `dependencies`, sorted by advisory ID and omitted when there are
none. Each entry has the same fields as a dependency vulnerability above
(including `reachability`, `call_path`, `call_trace` and `called_symbols`)
They are graded as a row named `stdlib` and are not counted in `summary`.

`call_path` is present only when `reachability` is `"called"`: one example of how the project reaches the vulnerable function, outermost frame first, condensed to the entry frame, the frame where each package hands over to the next, and the vulnerable function (at most 8 entries; `"..."` marks a cut). Consecutive entries are not necessarily direct callers. It is evidence that the code is on an execution path, not proof that the vulnerability is exploitable.

`call_trace` has one object per `call_path` entry, in the same order, with the frame's module, version and source position (`file`, `line`, `column`); `project` is true for the project's own code, and the `"..."` slot is `{"elided": true}`. A frame's position is the call it makes; the last entry's is the vulnerable function's declaration. `file` is relative to that frame's module, and is omitted when govulncheck reports an absolute path or one outside the module; `line` and `column` are kept. `called_symbols` lists every vulnerable symbol found called for the advisory (sorted, at most 20), since `call_path` shows only one. Neither field affects scoring or policy.

Absent `epss_score` means EPSS has no score for that CVE (expected — EPSS does
not score every CVE), the lookup failed, or the vuln has no CVE alias;
absent `in_kev` means the KEV catalog was not consulted (`false` means
"checked, not listed").

## Policy engine

`unisupply` ships two presets and accepts a custom JSON policy file. Policy
violations cause the binary to exit `2`, which is the convention CI systems
expect for a deliberate fail-fast. Without `--policy` or `--policy-preset` the
exit code ignores the grade: a grade of F still exits `0`.

```bash
# Built-in presets
unisupply ./ --policy-preset strict
unisupply ./ --policy-preset moderate

# Custom policy
unisupply ./ --policy ./security-policy.json
```

A minimal custom policy (every field is optional — see
[`pkg/policy/engine.go`](pkg/policy/engine.go) for the full set):

```json
{
  "max_grade": "C",
  "no_critical_vulns": true,
  "no_archived": true,
  "no_deprecated": true,
  "no_typosquatting": true,
  "no_unmaintained_months": 24,
  "max_depth": 8,
  "max_ci_score": 50,
  "blocked_modules": ["github.com/suspicious/pkg"],
  "allowed_modules": ["golang.org/x/", "github.com/unidoc/"]
}
```

Notable fields:

- `max_grade` — the worst letter allowed, `"A"` to `"F"` (`"C"` fails D and F).
  A grade that is Pending (a check it needs did not run) or missing **fails**
  this rule: a gate must not pass on "no result".
  A letter given without archived flags that could change it (`grade.archived_unread` not empty, no `GITHUB_TOKEN`) fails
  `"A"` and warns (`PASS (1 warning)`) with a looser maximum: set `GITHUB_TOKEN`.
- `allow_pending` — let a Pending grade pass `max_grade`. It is then printed as a
  warning (`PASS (1 warning): ...`) instead of failing.
- `no_known_vulns` / `no_critical_vulns` — fail on any vuln, or only on
  high/critical-severity vulns.
- `no_single_maintainer` — fail if any **direct** dependency has bus factor ≤ 1.
- `allowed_modules` — when set, acts as a strict whitelist applied to **direct
  dependencies only**; transitive modules are not gated by this rule. Each
  entry matches by exact module path or by path-prefix (`"golang.org/x/"`
  matches `golang.org/x/net`); glob patterns are not supported.
- `blocked_modules` — applies to direct and transitive dependencies, with the
  same exact-or-prefix matching rule.
- `max_ci_score` — gate on the CI/CD audit's own 0–100 score, which is separate from the grade (requires
  `--scan-ci`).
- `no_unmaintained_months`, `no_archived` and `no_deprecated` skip modules
  confirmed outside the build (`in_build: false`, in the module graph only). A
  module whose build membership is unknown is still checked, and so is a
  test-only module.
- `forbid_pseudo_versions` — fail on a pseudo-version pin, except for modules
  confirmed test-only or outside the build.
- `require_gosum_verified` — fail when `go mod verify` reported a checksum
  mismatch between go.sum and the local module cache. Honest-UNKNOWN outcomes
  (offline, no go.sum, toolchain unavailable) do not fail this rule.

Policy files are decoded strictly: any key that is not a recognized field is
rejected at load time (exit 1, naming the offending key), so a typo'd or
outdated rule name can never silently disable a check.

Ready-to-copy policy files and a field-by-field reference are in
[examples/](examples/policy-custom.md).

## Trust Index integration

`unisupply` can enrich a scan with curated trust data from a running
[unitrust](https://github.com/unidoc/unitrust) instance. The Trust Index is
UniDoc's curated database of Go module trustworthiness — it goes beyond what
public APIs and heuristics can tell you (vulnerability feeds, GitHub
contributor counts, release cadence) and adds **vetted, human-reviewed**
metadata: who actually maintains the package, what country and organization
they operate from, whether their identity is verified, the package's
stewardship status, and — when a module is known-risky — a recommended safer
alternative.

### How it works

When `--trust-index-url` points at a reachable unitrust instance, every
discovered module (direct and transitive) is sent in a **single batched
HTTP request** to `POST /api/v1/lookup`. The returned data is folded into
each dependency's report alongside the in-tree scanner output. No per-module
calls, no fan-out — one round trip regardless of graph size.

```bash
# Hosted unitrust (production CI)
unisupply ./ \
    --trust-index-url https://unitrust.unidoc.io \
    --format json --output results.json
```

### What the Trust Index adds to a report

For every module that unitrust has data on, the report gains:

| Field                     | What it tells you                                                    |
| ------------------------- | -------------------------------------------------------------------- |
| `trust_score`             | Composite curated trust score (0–100)                                |
| `maintainer_trust`        | Curated confidence in the maintainer's identity and track record     |
| `resilience_score`        | Project resilience as assessed by UniDoc, not just heuristics        |
| `security_score`          | Curated security posture (review history, hardening, response time)  |
| `community_score`         | Community health beyond raw star/fork counts                         |
| `maintainer_name`         | Real maintainer name where known                                     |
| `maintainer_org`          | Sponsoring or employing organization                                 |
| `maintainer_country`      | Maintainer jurisdiction — relevant for compliance / sanctions checks |
| `maintainer_verified`     | Whether UniDoc has verified the maintainer's identity                |
| `stewardship_status`      | `actively_maintained`, `community`, `inactive`, `abandoned`, …       |
| `safer_alternative`       | Recommended replacement module, if the entry is flagged as risky     |
| `is_unidoc_maintained`    | True for modules under UniDoc's own stewardship                      |

The full schema lives in
[`pkg/scanner/trustindex.go`](pkg/scanner/trustindex.go) (`TrustIndexEntry`).
Modules unitrust has no entry for are reported with their normal scanner
output unchanged.

### When to use it

- **CI gating** — combine `--trust-index-url` with `--policy-preset strict`
  to fail builds on known-risky modules whose risk isn't yet visible in the
  CVE feeds.
- **Procurement / vendor review** — the maintainer name, country, and
  verification flag are the fields enterprise reviewers actually need; they
  are not derivable from `go.mod` alone.
- **Supply-chain incident response** — the `safer_alternative` field
  short-circuits "what should we replace this with?" during a live
  incident.

### Privacy and operational notes

- The lookup payload contains **only module paths** — the same information
  that is already in your published `go.mod`. Versions are not transmitted,
  and the request includes no source code, scan results, or other
  project-identifying data.
- The whole feature is **opt-in and additive**. Leaving `--trust-index-url`
  off produces a fully self-contained scan — `unisupply` never reaches out
  to unitrust by default and has no implicit endpoint.
- Failures of the Trust Index call (network errors, non-200 responses) are
  surfaced as warnings; they do not abort the scan or change the grade
  derived from the in-tree scanners.
- **SSRF defense.** `--trust-index-url` requires `https` for all non-loopback
  hosts. RFC1918, link-local (`169.254/16`), and IPv6 ULA/link-local addresses
  are rejected unless `--trust-index-allow-private` is set. Use
  `--trust-index-allow-private` only when running a self-hosted unitrust on a
  private network — never in public CI where the flag value could be
  controlled by an attacker. A warning is printed before each POST so the
  destination is always visible in logs.

## Architecture

```
CLI (pflag)
  │
  ├── Parse go.mod / go.sum          pkg/parser/
  ├── Resolve dependency graph        pkg/resolver/
  ├── Run 9 security scanners        pkg/scanner/
  │   ├── Vulnerability (govulncheck)
  │   ├── Maintenance health
  │   ├── Maintainer analysis (GitHub API)
  │   ├── Typosquatting detection
  │   ├── Resilience scoring
  │   ├── CI/CD pipeline audit
  │   ├── Build file scanning
  │   ├── Integrity (go.mod/go.sum audit, go mod verify)
  │   └── Trust Index lookup (unitrust, optional)
  ├── Grade (A to F)                  pkg/grade/ (inputs from pkg/scorer/)
  ├── Evaluate org policies           pkg/policy/
  └── Generate reports                pkg/report/
      ├── Text (colored terminal)
      ├── JSON (machine-readable)
      ├── PDF (UniPDF)
      └── SBOM (CycloneDX, SPDX)
```

## Configuration reference

The full flag set is always available via:

```bash
unisupply --help
```

The most frequently used flags:

| Flag                    | Purpose                                                                                                              |
| ----------------------- |----------------------------------------------------------------------------------------------------------------------|
| `-f, --format`          | `text`, `json`, `pdf`, `sbom-cyclonedx`, `sbom-spdx`                                                                 |
| `-o, --output`          | Output file (default: stdout for text/json/sbom)                                                                     |
| `--github-token`        | GitHub API token (or `GITHUB_TOKEN` env)                                                                             |
| `--nvd-api-key`         | NVD API key for higher severity lookup rate limits (or `NVD_API_KEY` env) |
| `--trust-index-url`     | unitrust endpoint for curated trust scores                                                                           |
| `--trust-index-allow-private` | Allow `--trust-index-url` to target RFC1918/link-local addresses (self-hosted)                                       |
| `--policy-preset`       | `strict` or `moderate`                                                                                               |
| `--policy`              | Path to a custom policy JSON file                                                                                    |
| `--scan-workflows`      | Audit `.github/workflows/*.yml` and `*.yaml` only                                                                    |
| `--scan-ci`             | Full CI/CD audit: workflows + Dockerfile / Makefile / scripts                                                        |
| `--module-version`      | Published version of the scanned module (e.g. `v1.4.0`): also grades the module itself, from its own OSV advisories and archive status |
| `--grade-stdlib`        | Let the Go standard library decide the letter. It is always listed, with the Go release it was matched against, but not graded by default: its findings follow the toolchain that runs the scan |
| `--response-history`    | Look up how fast the project adopted its dependencies' fixes in the past (extra proxy and OSV requests; needs `--module-version`) |
| `--direct-only`         | Skip transitive dependencies                                                                                         |
| `-v, --verbose`         | Per-dependency breakdown                                                                                             |

Environment variables:

| Variable          | Purpose                                                          |
| ----------------- | ---------------------------------------------------------------- |
| `GITHUB_TOKEN`    | Higher GitHub API rate limits and access to private repositories |
| `NVD_API_KEY`     | Raises the NVD rate limit for CVE severity lookups (5 to 50 requests per 30 s) |
| `UNIDOC_LICENSE_API_KEY` | UniDoc license key (required for PDF report generation)   |

## Privacy and network access

`unisupply` collects **no telemetry**. It reads local files (`go.mod`,
`go.sum`, `.github/workflows/*.yml`, `Dockerfile`, `Makefile`, shell scripts)
and never uploads source code, scan results, or any project-identifying data.
The only information transmitted are the minimal identifiers listed below —
the same data already public in your `go.mod`.

| Host | What is sent | When | Disable |
| ---- | ------------ | ---- | ------- |
| `proxy.golang.org` | Module path + version, or a branch name (the GitHub default branch, else `main`, then `master`) | Maintenance and resilience scanners: release history, the latest version's `go.mod` (deprecation notice), and the default branch's head commit | always runs |
| `proxy.golang.org` | Module path + fixed version (or, for the standard library, `golang.org/toolchain@v0.0.1-go<version>.linux-amd64`) | Fix-release dates: the `.info` time of the first fixed version of an advisory, at most 8 lookups at a time, one per distinct fixed version | always runs when an advisory names a fixed version (no-op otherwise) |
| `proxy.golang.org` | Module path + fixed version | Fix compatibility: the `.mod` of each fixed version, to read its `go` directive (the Go release the fix needs), one lookup per distinct fixed version, at most 8 at a time | always runs when an advisory names a fixed version (no-op otherwise) |
| `proxy.golang.org` | The scanned module's path and its dependencies' module paths + fixed versions | Response history: the scanned module's version list (`@v/list`) and the `.info` and `.mod` of its newest releases, and the `.info` of the fixed versions of its dependencies' advisories; at most 2000 requests and 2 minutes per scan | only with `--response-history` (which needs `--module-version`); omit the flag to skip |
| `vuln.go.dev` | Module paths | Vulnerability scanner (`golang.org/x/vuln`) | always runs |
| `api.osv.dev` | Vulnerability ID (GO-\*, CVE-\*, or GHSA-\*), and its GHSA/CVE alias IDs (at most 4 aliases per advisory) | Severity enrichment when a vuln has unknown severity: the advisory's own record, then its alias records (GHSA first, then CVE; CVSS v3 vectors are scored locally) | always runs (no-op when no vulns) |
| `api.osv.dev` | The scanned module's path and version (one `POST /v1/query`, paged up to 10 pages) | The scanned module's own advisories: those that affect exactly that version, graded like a dependency's | always runs when the module's version is known (no-op otherwise) |
| `api.osv.dev` | Your direct dependencies' module paths (one `POST /v1/query` per dependency, at most 60 dependencies, paged up to 5 pages; no versions) | Response history: the advisories of each dependency, to find the versions that fixed them | only with `--response-history` (which needs `--module-version`); omit the flag to skip |
| `services.nvd.nist.gov` | CVE ID | Severity enrichment when a CVE alias exists and OSV and its alias records have no severity | always runs (no-op if no CVE alias); the NVD API key, when set, is sent as the `apiKey` header to this host only |
| `api.github.com` | Repo owner/name | Maintainer scanner (repo metadata, owner profile, contributor list); with a token, also the default branch's latest commit when the module proxy cannot answer the branch query | always runs; a token raises rate limits |
| `api.github.com` | The GitHub token only; no module data | Token validation: one request to `/rate_limit` (retried up to twice on a network error or 5xx), after the dependency graph is resolved and before any scanner runs | only when a GitHub token is supplied, the project has dependencies (or `--require-github-token` is set), and `--offline` is not set; omit the token to skip |
| `api.github.com` | Repo owner/name | Resilience scanner (governance file checks, unauthenticated) | always runs for GitHub-hosted deps |
| `api.github.com` | CVE ID | GHSA severity enrichment (only when a CVE alias exists and OSV, its alias records and NVD have no severity) | always runs (no-op if no CVE alias) |
| `api.first.org` | CVE IDs (batched) | EPSS exploitation-probability lookup for flagged CVEs | always runs (no-op if no CVE alias); 24h cache |
| `www.cisa.gov` | Nothing (bulk catalog download, no identifiers sent) | CISA KEV known-exploited lookup | always runs (no-op when no vulns); 24h cache |
| `<trust-index-url>` | Module paths (no versions, no source) | Trust Index lookup | opt-in — omit `--trust-index-url` |
| `cloud.unidoc.io` | License key + metered usage counters (doc count, package version, hostname, local IP, MAC address); no source, no scan results | PDF report generation, only when `UNIDOC_LICENSE_API_KEY` is set | opt-in — omit `--format pdf` |

**GitHub token validation.** When a token is supplied, `unisupply` checks it
once, after resolving the dependency graph and before any scanner runs, with a
request to `api.github.com/rate_limit` (which GitHub does not count against your
rate limit). A network error or 5xx is retried twice, with a short backoff,
before the token is treated as not validated. GitHub answers 401 to every
request that carries a bad token rather than serving it anonymously, so without
this check a rejected token silently degrades every GitHub lookup. If the token
is rejected, the scan warns (`GitHub token rejected (401) — continuing
unauthenticated`), adds the same notice to the report's warnings, and runs
without it. With `--require-github-token`, a rejected token exits with code 3,
and so does one that could not be validated: a network error or any response
other than 200 and 401 (for example 403, 429 or 5xx). Without the flag, a token
that could not be validated is used as is, with a warning. `--offline` skips the
check.

**Not contacted directly:** `sum.golang.org` and `pkg.go.dev` are never called by unisupply itself; no analytics beacon, crash reporter, or telemetry endpoint. Note that the Integrity scanner shells out to `go mod verify`, which checks the **local module cache** against go.sum — normally a fully offline operation. On a cold cache the `go` toolchain may fetch missing module metadata through your configured `GOPROXY` and verify it against `sum.golang.org`, exactly as any `go build` would; `GOPRIVATE`/`GONOSUMDB` are honored as usual. unisupply adds no network host beyond what the `go` toolchain itself contacts.

**Trust Index disclosure.** The `--trust-index-url` call sends the full list
of discovered module paths — equivalent to your published `go.mod`. No
versions, no source. The feature is opt-in and off by default; see the
[Trust Index section](#trust-index-integration) for full details.

**Verify the contract yourself.** `--network-log` prints every outbound HTTP
request to stderr — method, host, purpose, status, size, duration — so you can
confirm the table above matches real behavior rather than taking it on trust:

```bash
unisupply ./ --network-log 2> net.log
grep -E '^NET (GET|POST|HEAD|PUT|PATCH|DELETE) ' net.log \
  | awk '{print $3}' | sort -u   # every host contacted
```

```
NET SUBPROCESS go mod graph (module proxy/VCS may be contacted by the go toolchain; see GOPROXY)
NET GET vuln.go.dev vulndb → 200 (59116 bytes, 55ms)
NET GET proxy.golang.org maintenance:latest → 200 (78 bytes, 380ms)
NET HEAD api.github.com resilience:governance → 403 (279 bytes, 55ms)
```

A response whose length the server does not declare (chunked, or transparently
decompressed) reports `? bytes`; a failed request reports `→ error: …` with the
URL stripped from the error text, so a failure cannot disclose a request path or
query that the success line would not have printed.

Traffic from child processes (`go mod graph`, `go list`, `go mod verify`)
cannot be logged per-request, so it is reported as a `NET SUBPROCESS`
lifecycle line naming what the `go` toolchain may contact. Requests are
written to stderr only — `--network-log --format json > out.json` still
produces clean JSON. The flag downgrades an auto-detected TTY progress
spinner to plain lines so the two do not overwrite each other; `--progress
none` stays silent.

**Air-gapped environments.** Allow only the hosts above at your network
boundary; each scanner degrades gracefully with explicit warnings when a
host is unreachable.

For a scan that makes **no outbound requests at all**, use `--offline`:

```bash
unisupply ./ --offline
```

Enforcement is not advisory. Every in-process request is refused before a
socket is opened, and the `go` toolchain is run with `GOPROXY=off` plus cleared
`GOPRIVATE`/`GONOPROXY`/`GONOSUMDB` and `GOSUMDB=off`, so child processes read
only your local module cache. Clearing the private-module patterns matters:
the toolchain checks them *before* it honors `GOPROXY=off`, so a `GOPRIVATE`
entry would otherwise let a matching module fetch directly from VCS, and the
checksum database has its own direct fallback. You can confirm this the same way
you confirm anything else here — combine the two flags and read the log:

```bash
unisupply ./ --offline --network-log 2> net.log
grep -c 'error: offline mode' net.log   # every attempt, refused
```

What `--offline` costs you, and how each loss is reported:

| Scanner | Offline behavior |
|---------|------------------|
| Vulnerability (govulncheck) | Skipped — warning states no local vuln DB mirror is configured; the grade is **Pending**, never a letter from a scan that did not look |
| Maintenance | Not measured — warning names the module count; a row whose upkeep could not be read has no letter (`-`) rather than a guessed one |
| Maintainer, Resilience | UNKNOWN; not used by the grade |
| **Grade** | **`PENDING` (no letter).** With no vulnerability data a letter would rest on upkeep alone, so the grade has none; `grade.pending` in JSON names the check that did not run and what is known anyway. A policy with `max_grade` fails on it unless `allow_pending` is set |
| Response history (`--response-history`) | Not run — no request is made, and no response-history context is shown |
| Module's own advisories, fix-release dates, the Go release each fix needs | Not queried — the lookup returns an error that is reported as pending, and fix dates stay on the advisory's date |
| Threat intel (EPSS/KEV) | Not reached — enrichment runs over collected CVEs, and none are collected offline |
| go.sum verification | Reported as `UNKNOWN (offline — verification skipped)`, never as a failure |
| GitHub token validation | Skipped — a supplied token is not checked; with `--require-github-token` a warning says so and the run continues |
| Typosquat, CI/CD, build files, `go.mod` integrity | Unaffected — these never used the network |

Degraded checks are marked, never fabricated: an unavailable signal is reported
as unavailable, and a missing check the grade needs makes the grade Pending, so
an offline scan cannot read as a clean bill of health.

`--offline` is rejected alongside `--trust-index-url` (a network service by
definition) and `--format pdf` (UniPDF validates its license over the network
before rendering). Use `--format text`, `json`, or `sbom-*` offline.

An offline scan cannot look up vulnerabilities, because govulncheck needs the Go
vulnerability database: its grade is Pending (no letter), never a clean result. A
documented local-mirror workflow is not yet available — track it before relying on
`--offline` for vulnerability findings.

## Documentation

- [docs/grading.md](docs/grading.md) — how the letter is decided (Grading v2)
- [docs/scanners.md](docs/scanners.md) — scanner reference
- [SECURITY.md](SECURITY.md) — vulnerability reporting and supported versions
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and PR process
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards and enforcement
- [CHANGELOG.md](CHANGELOG.md) — release notes (Keep a Changelog 1.1)
- [RELEASING.md](RELEASING.md) — maintainer release procedure
- [LICENSE](LICENSE) — Apache License 2.0

## License

The `unisupply` CLI binary is Apache License 2.0 — see [LICENSE](LICENSE) for the full text.

**Library-use note:** The PDF report package (`pkg/report/pdf`) depends on
[UniPDF v3](https://github.com/unidoc/unipdf/releases/tag/v3.69.0), a commercial product governed by
the [UniDoc EULA](https://unidoc.io/eula/). PDF generation requires a license
key via `UNIDOC_LICENSE_API_KEY` — see [unidoc.io](https://unidoc.io) for licensing options. Importing `pkg/report/pdf` in your own
application is subject to the UniDoc EULA; the rest of UniSupply carries no
such restriction.

See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for a full dependency
license inventory.
See [NOTICE](NOTICE) for required upstream attribution notices.

Copyright © UniDoc ehf.
