# unisupply — Go Supply Chain Risk Assessment CLI NEW NEW

## Overview

`unisupply` is an open-source CLI tool by UniDoc that analyzes Go module dependency chains and produces a risk assessment report. It takes a `go.mod` file (or a Go project directory) as input, resolves all direct and transitive dependencies, and evaluates each one for security vulnerabilities, maintenance health, and supply chain risk indicators.

**Repository:** `github.com/unidoc/unisupply`
**License:** Apache 2.0
**Language:** Go (pure Go, no CGo)

---

## Core Functionality

### Input
- Path to a `go.mod` file, or a directory containing one
- If no path is given, use the current working directory

### Processing Pipeline

1. **Parse go.mod** — extract module name, Go version, all `require` directives
2. **Resolve full dependency graph** — resolve all transitive (indirect) dependencies and build a complete dependency tree. Use `go mod graph` or parse `go.sum` if available. The tool should be able to work standalone without requiring the Go toolchain installed — if `go` is not available, fall back to parsing `go.mod` and `go.sum` directly (direct dependencies only in that case, with a warning).
3. **Vulnerability scan** — check every dependency (direct and transitive) against the Go vulnerability database (https://vuln.go.dev). Use the API at https://vuln.go.dev/ID.json or the bulk database. Flag any module+version combination with known CVEs.
4. **Maintenance health assessment** — for each dependency, determine:
   - Last commit date / last release date (via Go module proxy: https://proxy.golang.org)
   - Whether the module is archived or deprecated
   - Number of known maintainers (if determinable)
   - Time since last release
   - Whether the module has been replaced/forked
5. **Risk scoring** — assign each dependency a risk score (0-100, where 100 = highest risk) based on weighted factors:
   - Known vulnerabilities: HIGH weight (any known CVE = significant score increase)
   - Maintenance status: MEDIUM-HIGH weight (unmaintained > 2 years = high risk, > 1 year = medium)
   - Dependency depth: MEDIUM weight (deeply transitive = harder to audit)
   - Single maintainer: MEDIUM weight (bus factor risk)
   - Typosquatting indicators: LOW-MEDIUM weight (similar names to popular packages)
6. **Overall project risk score** — aggregate individual dependency scores into an overall supply chain health score

### Output Formats

The tool should support multiple output formats via a `--format` flag:

- **`text`** (default) — human-readable terminal output with color coding (red/yellow/green for risk levels)
- **`json`** — machine-readable JSON output for CI/CD integration
- **`pdf`** — enterprise-ready PDF risk report (use UniPDF for generation — this dogfoods our own product). Include UniDoc branding, summary dashboard, and per-dependency breakdown.

---

## CLI Interface

```
unisupply [flags] [path]

Flags:
  -f, --format string    Output format: text, json, pdf (default "text")
  -o, --output string    Output file path (default: stdout for text/json, "unisupply-report.pdf" for pdf)
  -v, --verbose          Show detailed information for each dependency
      --no-color         Disable color output
      --min-risk int     Only show dependencies with risk score >= this value (0-100)
      --direct-only      Only analyze direct dependencies (skip transitive)
      --timeout duration HTTP request timeout (default 30s)
  -h, --help             Show help
      --version          Show version

Examples:
  unisupply                          # Analyze current directory
  unisupply ./myproject              # Analyze specific project
  unisupply -f json -o report.json   # JSON output to file
  unisupply -f pdf                   # Generate PDF risk report
  unisupply --min-risk 50            # Only show medium+ risk dependencies
```

---

## Text Output Example

```
unisupply v0.1.0 — Go Supply Chain Risk Assessment
by UniDoc (unidoc.io)

Project: github.com/example/myproject
Go version: 1.22
Dependencies: 47 direct, 183 transitive (230 total)

═══════════════════════════════════════════════════
OVERALL SUPPLY CHAIN RISK SCORE: 62/100 (MEDIUM)
═══════════════════════════════════════════════════

HIGH RISK (3 dependencies)
──────────────────────────
● github.com/old/abandoned v1.2.3          Risk: 89/100
  ├─ ⚠ 2 known vulnerabilities (CVE-2024-1234, CVE-2024-5678)
  ├─ ⚠ Last release: 3 years ago
  ├─ ⚠ Repository archived
  └─ Used by: github.com/example/myproject (direct)

● github.com/some/library v0.9.1           Risk: 78/100
  ├─ ⚠ 1 known vulnerability (CVE-2025-9999)
  ├─ ⚠ Last release: 18 months ago
  └─ Used by: github.com/other/dep → github.com/some/library (transitive)

[...]

MEDIUM RISK (12 dependencies)
─────────────────────────────
[...]

LOW RISK (215 dependencies)
───────────────────────────
[summary only unless --verbose]

──────────────────────────
SUMMARY
  High risk:    3 (1.3%)
  Medium risk: 12 (5.2%)
  Low risk:   215 (93.5%)

  Vulnerabilities found: 5 across 3 dependencies
  Unmaintained (>2yr):   4 dependencies
  Unmaintained (>1yr):   9 dependencies

Report generated: 2026-03-21T14:30:00Z
Full report: unisupply -f pdf
Learn more: https://security.unidoc.io
```

---

## JSON Output Schema

```json
{
  "tool": "unisupply",
  "version": "0.1.0",
  "generated_at": "2026-03-21T14:30:00Z",
  "project": {
    "module": "github.com/example/myproject",
    "go_version": "1.22",
    "direct_dependencies": 47,
    "transitive_dependencies": 183,
    "total_dependencies": 230
  },
  "overall_risk_score": 62,
  "overall_risk_level": "MEDIUM",
  "summary": {
    "high_risk_count": 3,
    "medium_risk_count": 12,
    "low_risk_count": 215,
    "total_vulnerabilities": 5,
    "unmaintained_2yr": 4,
    "unmaintained_1yr": 9
  },
  "dependencies": [
    {
      "module": "github.com/old/abandoned",
      "version": "v1.2.3",
      "direct": true,
      "risk_score": 89,
      "risk_level": "HIGH",
      "dependency_path": ["github.com/example/myproject"],
      "vulnerabilities": [
        {
          "id": "GO-2024-1234",
          "aliases": ["CVE-2024-1234"],
          "summary": "Description of vulnerability",
          "severity": "HIGH",
          "fixed_version": "v1.3.0"
        }
      ],
      "maintenance": {
        "last_release": "2023-01-15T00:00:00Z",
        "months_since_release": 38,
        "archived": true,
        "deprecated": false
      },
      "risk_factors": [
        "known_vulnerabilities",
        "unmaintained",
        "archived"
      ]
    }
  ]
}
```

---

## PDF Report Structure

Generate using UniPDF (github.com/unidoc/unipdf). The PDF should be a professional enterprise-grade document suitable for sharing with security teams.

### Pages:
1. **Cover page** — "Go Supply Chain Risk Assessment" title, project name, date, UniDoc branding, overall risk score as a large visual indicator
2. **Executive summary** — one page with key metrics: total deps, risk distribution (pie chart or bar), top vulnerabilities found, overall risk score with explanation
3. **High risk dependencies** — one section per high-risk dependency with full details: vulnerability list, maintenance status, dependency path, remediation suggestions
4. **Medium risk dependencies** — condensed table format
5. **Low risk dependencies** — summary table (module, version, score)
6. **Methodology** — brief explanation of scoring methodology
7. **Footer on every page** — "Generated by unisupply — unidoc.io/unisupply"

---

## Data Sources & APIs

| Data | Source | Endpoint |
|------|--------|----------|
| Vulnerability data | Go Vulnerability Database | `https://vuln.go.dev/` — use the `golang.org/x/vuln` package or fetch from API |
| Module versions & timestamps | Go Module Proxy | `https://proxy.golang.org/{module}/@v/list` and `{module}/@v/{version}.info` |
| Dependency graph | Go toolchain | `go mod graph` (if available) or parse `go.mod`/`go.sum` |
| Module deprecation | Go Module Proxy | `.info` endpoint includes deprecation notices |
| Maintainer & repo metadata | GitHub API | `https://api.github.com/repos/{owner}/{repo}` — contributors, archive status, org info (v0.2.0) |
| GitHub Actions metadata | GitHub Actions Marketplace | Verify action authors, check for known compromised actions (v0.3.0) |

### Important notes on APIs:
- Respect rate limits on all external services
- Cache responses locally during a single run (don't re-fetch the same module)
- All HTTP requests should have configurable timeout (default 30s)
- The tool should work offline with degraded functionality (skip vuln check, skip maintenance check, only report dependency tree)

---

## Project Structure

```
unisupply/
├── cmd/
│   └── unisupply/
│       └── main.go              # CLI entry point, flag parsing
├── pkg/
│   ├── parser/
│   │   ├── gomod.go             # go.mod and go.sum parsing
│   │   └── workflow.go          # GitHub Actions workflow parsing (v0.3.0)
│   ├── resolver/
│   │   └── graph.go             # Dependency graph resolution
│   ├── scanner/
│   │   ├── vuln.go              # Vulnerability database scanning
│   │   ├── maintenance.go       # Maintenance health checking
│   │   ├── maintainer.go        # Maintainer/ownership analysis (v0.2.0)
│   │   ├── typosquat.go         # Typosquatting detection (v0.2.0)
│   │   └── ci.go                # CI/CD pipeline scanning (v0.3.0)
│   ├── scorer/
│   │   └── risk.go              # Risk scoring algorithm
│   └── report/
│       ├── text.go              # Terminal text output
│       ├── json.go              # JSON output
│       └── pdf.go               # PDF report generation (using UniPDF, v0.2.0)
├── go.mod
├── go.sum
├── README.md
├── LICENSE                      # Apache 2.0
└── .goreleaser.yml              # For building releases
```

---

## Risk Scoring Algorithm

Each dependency gets a score from 0-100 based on these weighted factors:

| Factor | Weight | Scoring |
|--------|--------|---------|
| Known vulnerabilities | 40% | Any CRITICAL CVE = 100, HIGH = 80, MEDIUM = 50, LOW = 25. Multiple vulns stack (capped at 100). |
| Maintenance freshness | 25% | Last release <6mo = 0, 6-12mo = 25, 12-24mo = 60, >24mo = 90, archived = 100 |
| Dependency depth | 15% | Direct = 0, 1 level transitive = 20, 2+ levels = 40 |
| Maintainer risk | 10% | Multiple maintainers = 0, single = 50, unknown = 30 |
| Module maturity | 10% | v1+ with stable releases = 0, v0.x = 30, no tags = 50 |

**Overall project score** = weighted average of all dependency scores, with higher-risk dependencies weighted more heavily (a single critical dependency should pull the overall score up).

**Risk levels:**
- 0-25: LOW (green)
- 26-50: MEDIUM (yellow)  
- 51-75: HIGH (orange)
- 76-100: CRITICAL (red)

---

## MVP Scope (v0.1.0)

For the first release, focus on:

1. ✅ Parse go.mod and resolve dependency graph (using `go mod graph`)
2. ✅ Vulnerability scanning against Go vuln DB
3. ✅ Basic maintenance health check (last release date from Go proxy)
4. ✅ Risk scoring
5. ✅ Text output with colors
6. ✅ JSON output

---

## v0.2.0 — PDF Reports & Maintainer Intelligence

1. ⬜ **PDF risk report** — enterprise-ready PDF using UniPDF (dogfooding our own product)
2. ⬜ **Typosquatting detection** — flag modules with names suspiciously similar to popular packages
3. ⬜ **Maintainer analysis** — for each dependency, determine:
   - Number of maintainers / contributors with write access
   - Whether it's a single-person project (bus factor = 1)
   - Maintainer activity pattern (active, sporadic, gone)
   - Whether the GitHub org/user is verified or anonymous
   - Corporate vs personal ownership
4. ⬜ **Takeover candidate flagging** — automatically identify dependencies that are:
   - Widely used but unmaintained (high star count + no recent commits)
   - Single maintainer who has gone inactive
   - Archived but still pulled as a dependency
   - These are flagged as "stewardship candidates" — packages UniDoc or the enterprise customer could adopt and maintain. Output includes a separate section: "Packages eligible for maintenance takeover"

---

## v0.3.0 — CI/CD Pipeline Scanning & Workflow Audit

Accept additional inputs beyond go.mod to assess the full build pipeline:

1. ⬜ **GitHub Actions workflow scanning** — accept `.github/workflows/*.yml` as input or scan them from a project directory. Assess:
   - Use of pinned action versions vs floating tags (e.g., `uses: actions/checkout@v4` vs `uses: actions/checkout@abc123` — floating tags can be hijacked)
   - Third-party actions from unknown/unverified authors
   - Actions with excessive permissions (`permissions: write-all`)
   - Secrets exposure patterns (secrets passed to untrusted steps)
   - Self-hosted runner risks
   - Supply chain attack vectors through CI (compromised actions injecting malicious code into builds)
2. ⬜ **Build pipeline assessment** — analyze Dockerfiles, Makefiles, and build scripts for:
   - Unpinned base images
   - `curl | bash` install patterns
   - Downloading binaries without checksum verification
3. ⬜ **AI-generated code risk indicators** — flag patterns common in AI-generated supply chain attacks:
   - Recently created modules with names mimicking established packages
   - Modules with suspiciously rapid initial adoption
   - Dependencies that appeared after a project started using AI coding tools
   - Unusual import patterns (importing packages that don't match stated purpose)

### New CLI flags for v0.3.0:

```
  --scan-workflows       Scan GitHub Actions workflow files in .github/workflows/
  --scan-ci              Scan CI/CD configuration (GitHub Actions, Dockerfile, Makefile)
  --workflow-path string Path to workflow directory (default ".github/workflows")
```

### New output sections:

**CI/CD Risk Assessment** — separate section in all output formats showing:
- Workflow-by-workflow risk breakdown
- List of unverified/unpinned third-party actions
- Permissions audit
- Recommended fixes (pin to SHA, reduce permissions, etc.)

---

## Future Considerations (v0.4.0+)

- **Continuous monitoring mode** — watch a go.mod and alert on new vulnerabilities or maintainer changes
- **Integration with security.unidoc.io** — upload reports, track risk over time, compare across projects
- **SBOM generation** — produce CycloneDX or SPDX format Software Bill of Materials
- **Policy engine** — define organizational policies (e.g., "no dependencies with risk score > 70", "no single-maintainer packages in production") and fail CI builds on violations
- **Enterprise reporting dashboard** — aggregated view across multiple projects for enterprise customers

---

## README.md Content

The README should include:
- Clear description: "Scan your Go project's supply chain for security risks"
- Installation: `go install github.com/unidoc/unisupply/cmd/unisupply@latest`
- Quick start with example output
- All CLI flags documented
- Link to https://security.unidoc.io
- "Built by UniDoc — Enterprise Go Platform" with link to unidoc.io
- Badge: Go version, license, build status

---

## Notes

- Pure Go, zero CGo — must cross-compile easily
- Minimal dependencies — practice what we preach about supply chain hygiene
- The tool itself should have a clean, small dependency tree
- Every dependency we use should be justified
- This tool is open source and free — it serves as a credibility builder and lead generator for our enterprise services
- Enterprise customers who want deeper analysis, ongoing monitoring, or custom reports can contact us at security@unidoc.io
