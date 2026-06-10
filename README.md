# unisupply

> Go supply chain risk assessment — vulnerabilities, maintainer health, typosquatting, AI-generated code risk, CI/CD audit, SBOM, policy enforcement.

<!--
TODO (PR 11 / M5.5): the repository is currently private. When it goes public,
replace this comment block with the live badge row below.

[![CI](https://github.com/unidoc/unisupply/actions/workflows/ci.yml/badge.svg)](https://github.com/unidoc/unisupply/actions/workflows/ci.yml)
[![Release](https://github.com/unidoc/unisupply/actions/workflows/release.yml/badge.svg)](https://github.com/unidoc/unisupply/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/unidoc/unisupply)](https://goreportcard.com/report/github.com/unidoc/unisupply)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Coverage badge intentionally omitted — no Codecov / Coveralls integration yet.
Do not surface an integrity signal that is not backed by a verification
mechanism (OWASP SCVS V4.1).
-->

## What it does

`unisupply` analyzes a Go project's full module dependency chain and produces a
supply chain risk assessment. It runs nine focused scanners — vulnerability
lookup, maintenance health, maintainer analysis, typosquatting detection,
resilience scoring, AI-generated code heuristics, CI/CD pipeline audit, build
file inspection, and Trust Index lookup — combines the in-tree scanner signals
into a weighted risk score per dependency, attaches the optional Trust Index
data to each report alongside that score, and renders the result as a colored terminal
summary, machine-readable JSON, an enterprise PDF report, or a CycloneDX /
SPDX SBOM. A built-in policy engine fails CI on configurable thresholds
(critical vulns, max age, blocked modules, unpinned actions, ...).

It is intended for engineering teams that need to make merge-time and
release-time decisions about third-party Go code.

## Install

```bash
# Latest release (Go 1.25+ required)
go install github.com/unidoc/unisupply/cmd/unisupply@latest

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

A typical text-format run against a small project looks like this (truncated
for the README — your output will list every direct and transitive
dependency):

```
unisupply v0.4.0 — Go Supply Chain Risk Assessment
by UniDoc (unidoc.io)

Project: github.com/example/app
Dependencies: 4 direct, 38 transitive (42 total, 113 graph edges)

═══════════════════════════════════════════════════
OVERALL SUPPLY CHAIN RISK SCORE: 26/100 (MEDIUM)
═══════════════════════════════════════════════════

HIGH RISK (3 dependencies)
────────────────────────────────────────
● golang.org/x/net      Risk: 51/100  (transitive)
  ├─ 4 known vulnerabilities with available fixes
  ├─ Resilience: 70/100 (frequent cadence, 53 releases)
  └─ Score: vuln=100×40% maint=0×25% depth=0×15% maintainer=0×10% maturity=0×10%

MEDIUM RISK (19 dependencies)   [...]
LOW RISK (20 dependencies)      [use --verbose to see details]

PACKAGES ELIGIBLE FOR MAINTENANCE TAKEOVER
────────────────────────────────────────
  ● widely-used/inactive-pkg   Activity: inactive   Bus factor: 1
```

Pass `--verbose` for full per-dependency breakdowns including the dependency
path that pulled the module in.

## Scanners

| Scanner          | What it checks                                          | Data source                |
| ---------------- | ------------------------------------------------------- | -------------------------- |
| Vulnerability    | Known CVEs in dependencies                              | Go vuln DB (vuln.go.dev)   |
| Maintenance      | Last release, archive status, deprecation               | Go Module Proxy            |
| Maintainer       | Contributors, bus factor, activity, org verification    | GitHub API                 |
| Typosquatting    | Levenshtein-similarity to ~75 well-known modules        | Built-in list              |
| Resilience       | Release cadence, governance files, version scheme       | GitHub API                 |
| AI-Generated     | Fresh modules, few releases, generic names (heuristics) | Module metadata            |
| CI/CD            | Action pinning, permissions, secret exposure            | `.github/workflows/*.yml`  |
| Build files      | Unpinned Docker images, `curl \| bash` patterns         | Dockerfile, Makefile, *.sh |
| Trust Index      | Curated trust scores                                    | unitrust API (optional)    |

The risk score is a weighted composite per dependency:

```
Per-Dep Risk Score (0–100) =
    Vulnerabilities × 0.40
  + Maintenance     × 0.25
  + Depth           × 0.15
  + Maintainer Risk × 0.10
  + Maturity        × 0.10
  + Typosquat Penalty      (0–20)
  + AI-Gen Penalty         (0–15)
  + Low-Resilience Penalty (0–6)  // adds when resilience score < 30
```

**Project headline score** is the maximum of four candidates — it never dilutes a single bad actor into a healthy-looking average:

```
Headline = max(severity_adjusted, p95_dep_risk, archived_floor, cve_floor)
```

| Candidate | Description |
| ------------------- | ----------------------------------------------------------------- |
| `severity_adjusted` | Step-function over reachability-downgraded CVE counts |
| `p95_dep_risk` | 95th-percentile of per-dep risk scores (nearest-rank) |
| `archived_floor` | HIGH floor (51) when any transitive dep is archived; 60 for a direct archived dep |
| `cve_floor` | Floor based on post-reachability CVE tier: called CRITICAL→60, called HIGH→55, imported CRITICAL/HIGH→40, required CRITICAL→40 |

**Example.** A project with 1 archived direct dep, 40 healthy deps, and one imported HIGH CVE:

| Candidate | Value |
| ------------------- | ----- |
| `severity_adjusted` | 10 |
| `p95_dep_risk` | 12 |
| `archived_floor` | 60 ← direct archived dep |
| `cve_floor` | 40 |

Result: **60 / HIGH — Driver: archived\_floor (direct archived dep)**

`MeanDepRiskScore` is still available as the top-level JSON field `mean_dep_risk_score` for trend lines, but is not the headline.

Levels: **LOW** 0–25 · **MEDIUM** 26–50 · **HIGH** 51–75 · **CRITICAL** 76–100.

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

```json
{
  "module": "golang.org/x/net",
  "version": "v0.35.0",
  "risk_score": 72,
  "risk_level": "HIGH",
  "vulnerabilities": [
    {
      "id": "GO-2025-0001",
      "aliases": ["CVE-2025-12345"],
      "summary": "HTTP/2 request smuggling in golang.org/x/net/http2",
      "severity": "HIGH",
      "fixed_version": "v0.36.0",
      "reachability": "called"
    },
    {
      "id": "GO-2025-0002",
      "aliases": ["CVE-2025-67890"],
      "summary": "DoS in unused websocket handler",
      "severity": "MEDIUM",
      "fixed_version": "v0.36.0",
      "reachability": "imported"
    }
  ]
}
```

Absent `reachability` on a non-govulncheck finding is treated as `"called"`.

## Policy engine

`unisupply` ships two presets and accepts a custom JSON policy file. Policy
violations cause the binary to exit `2`, which is the convention CI systems
expect for a deliberate fail-fast.

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
  "max_overall_score": 50,
  "max_risk_score": 75,
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

- `no_known_vulns` / `no_critical_vulns` — fail on any vuln, or only on
  high/critical-severity vulns.
- `no_single_maintainer` — fail if any **direct** dependency has bus factor ≤ 1.
- `allowed_modules` — when set, acts as a strict whitelist applied to **direct
  dependencies only**; transitive modules are not gated by this rule. Each
  entry matches by exact module path or by path-prefix (`"golang.org/x/"`
  matches `golang.org/x/net`); glob patterns are not supported.
- `blocked_modules` — applies to direct and transitive dependencies, with the
  same exact-or-prefix matching rule.
- `max_ci_score` — gate on the CI/CD scanner's overall risk score (requires
  `--scan-ci`).

<!-- TODO (PR 08 / M6.5): once the examples/ directory lands, link to ready-to-copy policy files here. -->

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
  surfaced as warnings; they do not abort the scan or alter risk scores
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
  │   ├── AI-generated code risk
  │   ├── CI/CD pipeline audit
  │   ├── Trust Index lookup (unitrust, optional)
  │   └── Build file scanning
  ├── Compute risk scores             pkg/scorer/
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

| Flag                    | Purpose                                                       |
| ----------------------- | ------------------------------------------------------------- |
| `-f, --format`          | `text`, `json`, `pdf`, `sbom-cyclonedx`, `sbom-spdx`          |
| `-o, --output`          | Output file (default: stdout for text/json/sbom)              |
| `--github-token`        | GitHub API token (or `GITHUB_TOKEN` env)                      |
| `--trust-index-url`     | unitrust endpoint for curated trust scores                    |
| `--trust-index-allow-private` | Allow `--trust-index-url` to target RFC1918/link-local addresses (self-hosted) |
| `--policy-preset`       | `strict` or `moderate`                                        |
| `--policy`              | Path to a custom policy JSON file                             |
| `--scan-workflows`      | Audit `.github/workflows/*.yml` and `*.yaml` only             |
| `--scan-ci`             | Full CI/CD audit: workflows + Dockerfile / Makefile / scripts |
| `--min-risk`            | Hide dependencies below the given score                       |
| `--direct-only`         | Skip transitive dependencies                                  |
| `-v, --verbose`         | Per-dependency breakdown                                      |

Environment variables:

| Variable          | Purpose                                                          |
| ----------------- | ---------------------------------------------------------------- |
| `GITHUB_TOKEN`    | Higher GitHub API rate limits and access to private repositories |
| `UNIDOC_LICENSE_API_KEY` | UniDoc license key (required for PDF report generation)   |

## Documentation

- [docs/scanners.md](docs/scanners.md) — scanner reference and the canonical risk-scoring formula
- [SECURITY.md](SECURITY.md) — vulnerability reporting and supported versions
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and PR process
- [CHANGELOG.md](CHANGELOG.md) — release notes (Keep a Changelog 1.1)
- [RELEASING.md](RELEASING.md) — maintainer release procedure
- [LICENSE](LICENSE) — Apache License 2.0

## License

The `unisupply` CLI binary is Apache License 2.0 — see [LICENSE](LICENSE) for the full text.

**Library-use note:** The PDF report package (`pkg/report/pdf`) depends on
[UniPDF](https://github.com/unidoc/unipdf), a commercial product governed by
the [UniDoc EULA](https://unidoc.io/eula/). PDF generation requires a license
key via `UNIDOC_LICENSE_API_KEY` — free metered keys are available at
[unidoc.io](https://unidoc.io). Importing `pkg/report/pdf` in your own
application is subject to the UniDoc EULA; the rest of UniSupply carries no
such restriction.

See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for a full dependency
license inventory.

Copyright © UniDoc ehf.
