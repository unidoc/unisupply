# UniDoc Supply Chain Security — Developer Guide

## What is this?

An open-source CLI tool that **analyzes Go module dependency chains and produces a supply chain assessment: one letter grade, A to F, with the evidence behind it**. It scans for vulnerabilities, evaluates project upkeep and maintainer health, detects typosquatting, audits CI/CD pipelines, and generates enterprise-grade PDF reports.

Open source credibility builder for UniDoc's enterprise services. Dogfoods UniDoc's own products (UniPDF for PDF generation).

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
  │   ├── Integrity (go.mod replace/exclude audit)
  │   └── Trust Index lookup (unitrust)
  ├── Grade (A to F)                  pkg/grade/ (fed by pkg/scorer/ signals)
  ├── Evaluate org policies           pkg/policy/
  └── Generate reports                pkg/report/
      ├── Text (colored terminal)
      ├── JSON (machine-readable)
      ├── PDF (enterprise, UniPDF)
      └── SBOM (CycloneDX, SPDX)
```

## Grading (rules version 2)

The published result is one letter, A to F. The reference is `docs/grading.md`; the code is `pkg/grade`, and if they
disagree the code wins.

```
row score = max(vulnerability score, upkeep score)      // per row; the module itself is a row too
letter    = band of the worst row                       // A 0-10, B 11-25, C 26-50, D 51-75, F 76-100
```

- **Vulnerability score** comes from the severity and the govulncheck reachability tier (called, imported, graph-only).
  A called finding on the CISA KEV list is at least F. Graph-only findings are shown, not graded.
- **Upkeep score**: archived or deprecated rows count, but only up to C. A quiet project scores 0.
- **Whole-tree rules** only raise the letter (many called high or critical findings, a called KEV finding, a checksum
  mismatch from `go mod verify`).
- **Pending**: when a check the letter needs did not run (vulnerability scan, scan did not finish, the module's own
  status, a dependency's maintenance data), there is **no letter**. `grade.pending` names the check. A row whose upkeep
  could not be read has an empty letter (`-`). A gate must treat Pending as "no result", never as a pass. A cached KEV
  catalog older than 30 days (`scanner.KEVMaxStaleAge`) is no catalog (Pending `known_exploited`); up to 30 days it is used
  and the note states its age. On Pending the deprecated JSON scores (`overall_risk_score`, `headline.score`, a
  dependency's `risk_score`) are omitted, never 0.
- **`archived_unread`**: an unread archived flag adds at most 20 to a row, so `grade.archived_unread` and its note list
  only the modules whose flag could raise the letter (computed in `pkg/grade`); empty on C, D and F.
- **Zero-dependency modules** still run the vulnerability scan and list stdlib findings (not graded without
  `--grade-stdlib`; a failed scan is Pending only with it). `StdlibScanned` follows the scan outcome. The scan runs through
  the `scanVulns` seam in `pkg/runner` (tests stub it). `scan.govulncheck_version` is `golang.org/x/vuln`'s version from the
  build info, never unisupply's own.
- **Toolchain check**: govulncheck runs in-process with the Go unisupply was built with. `scanner.CheckToolchain(scanGo)`
  (exported; gorisk calls it at startup) returns "this unisupply was built with go1.26.9 and cannot scan code that needs
  go1.27.2; rebuild unisupply with go1.27.2 or newer" when `scanGo` is newer (compared with `go/version`, so rc and beta forms
  order correctly). `ScanVulnsWithOptions` runs it on the project's resolved Go before starting, and rewrites the loader's "file
  requires newer Go version" error to the same sentence; it becomes the `vulnerability_scan` Pending reason. Tests inject
  `builtWithGo`.
- **Fix age at release**: with `--module-version`, `scanner.ModuleVersionTime` (proxy `.info`, cached) gives the scanned version's
  release time (`grade.Input.SelfReleasedAt`); `response.fix_age_at_release_days` is set when the fix predates it by a day or
  more (the `selfReleaseTime` seam in `pkg/runner`).
- **Estimated**: a letter that an unpublished severity (scored as medium) could change is shown with `*` (`C*`): the grade is recomputed with every such severity as low and as critical.
- The 0-100 numbers in the rows (and `grade.score`) are policy values that pick a band. They are shown beside the
  letter for traceability; they are not a measurement and not a risk score.
- **Build membership**: a module confirmed outside the build (`in_build: false`) or confirmed test-only is discounted or
  not graded as the rules say; an unknown classification never discounts.
- The CI/CD audit is not part of the grade. It keeps its own 0-100 score (`max_ci_score`).
- The old 0-100 risk score, headline candidates (`overall_risk_*`, `headline*`), AI-generation penalty and the takeover
  list are **not published** in any output. `pkg/scorer` still computes them internally (see "Internal scorer (not
  published)" in `docs/scanners.md`); only its signals (reachability, build membership, test-only, maintenance state)
  feed the grade.

## The 9 Scanners

| Scanner | What it checks | Data source |
|---------|---------------|-------------|
| **Vulnerability** | Known CVEs in dependencies | Go vuln DB (vuln.go.dev) |
| **Maintenance** | Last release, default-branch activity, archive status, deprecation (incl. go.mod `// Deprecated:`) | Go Module Proxy |
| **Maintainer** | Contributors, bus factor, activity, org verification | GitHub API |
| **Typosquatting** | Similar names to well-known packages (Levenshtein) | Built-in list (~75 modules) |
| **Resilience** | Release cadence, governance files, version scheme | GitHub API |
| **CI/CD** | Action pinning, permissions, secret exposure | .github/workflows/*.yml |
| **Build Files** | Unpinned Docker images, curl\|bash patterns | Dockerfile, Makefile, *.sh |
| **Integrity** | `go.mod` replace/exclude directive audit | `go.mod` (offline) |
| **Trust Index** | Package trust scores from curated database | unitrust API |

## Integration with unitrust

unisupply optionally queries the [unitrust](../unitrust/) Trust Index API:

```bash
unisupply --trust-index-url http://localhost:8080 ./
```

This calls `POST /api/v1/lookup` with all discovered modules and enriches the report with curated trust scores, maintainer verification, and stewardship data.

## Tech stack

- Go 1.26.9, no CGo
- `github.com/spf13/pflag` — CLI flags
- `github.com/unidoc/unipdf/v5` — PDF report generation (dogfooding)
- `github.com/unidoc/unichart` — Charts in PDF reports
- `golang.org/x/vuln` — Go vulnerability database
- `gopkg.in/yaml.v3` — GitHub Actions workflow parsing

## Key files

| File | Purpose |
|------|---------|
| `cmd/unisupply/main.go` | CLI entry point, orchestrates full pipeline |
| `pkg/parser/gomod.go` | Parse go.mod and go.sum |
| `pkg/parser/workflow.go` | Parse GitHub Actions YAML |
| `pkg/resolver/graph.go` | Resolve full dependency tree |
| `pkg/scanner/vuln.go` | Vulnerability scanning |
| `pkg/scanner/maintenance.go` | Maintenance health checks |
| `pkg/scanner/maintainer.go` | GitHub maintainer analysis |
| `pkg/scanner/typosquat.go` | Typosquatting detection |
| `pkg/scanner/resilience.go` | Resilience scoring |
| `pkg/scanner/aigen.go` | AI-generation heuristic (no longer run; not published) |
| `pkg/scanner/ci.go` | CI/CD pipeline audit |
| `pkg/scanner/trustindex.go` | unitrust API integration |
| `pkg/scanner/integrity.go` | `go.mod` replace/exclude directive audit |
| `pkg/grade/` | The grade: rows, letter, Pending (Grading v2) |
| `pkg/scorer/risk.go` | Scanner signals and the internal (unpublished) 0-100 score |
| `pkg/policy/engine.go` | Organizational policy evaluation |
| `pkg/report/text.go` | Terminal output |
| `pkg/report/json.go` | JSON output |
| `pkg/report/pdf.go` | PDF report (UniPDF) |
| `pkg/report/sbom.go` | SBOM generation (CycloneDX, SPDX) |
| `spec/` | Full product specification |

## Usage

```bash
# Basic scan of current project
unisupply ./

# Full scan with PDF report and trust index
unisupply ./ \
  --format pdf \
  --output report.pdf \
  --github-token $GITHUB_TOKEN \
  --trust-index-url http://localhost:8080

# JSON output for CI/CD
unisupply ./ --format json --output results.json

# SBOM generation
unisupply ./ --format sbom-cyclonedx --output sbom.json

# Policy enforcement (exits 2 on violation)
unisupply ./ --policy-preset strict
unisupply ./ --policy ./my-policy.json

# Also grade the module itself at a published version
unisupply ./ --module-version v1.4.0

# Progress output (default: auto — TTY spinner if stderr is a terminal,
# timestamped lines otherwise). Always writes to stderr; never contaminates
# stdout, so it is safe with `--format json` piped to a consumer.
unisupply ./ --progress plain 2> progress.log         # capture log
unisupply ./ --progress none --format json > out.json # fully silent

# Observe outbound network traffic (stderr only; verifies the README contract)
unisupply ./ --network-log 2> net.log
```

### Environment variables

| Var | Purpose |
|-----|---------|
| `GITHUB_TOKEN` | GitHub API access (higher rate limits, private repos) |
| `NVD_API_KEY` | NVD API key (higher rate limit for CVE severity lookups) |
| `UNIDOC_LICENSE_API_KEY` | UniDoc license key (for PDF generation) |

## Policy engine

Built-in presets: `strict`, `moderate`. Or custom JSON:

```json
{
  "max_grade": "C",
  "no_critical_vulns": true,
  "no_single_maintainer": true,
  "no_unmaintained_months": 18,
  "no_archived": true,
  "no_typosquatting": true,
  "max_ci_score": 50,
  "forbid_replace_redirect": true,
  "require_gosum_verified": true,
  "allow_pending": false,
  "blocked_modules": ["github.com/suspicious/pkg"],
  "allowed_modules": ["golang.org/x/", "github.com/unidoc/"]
}
```

See `pkg/policy/engine.go` for the full schema and `examples/policy-custom.json`
for an example reference.

`max_grade` is the worst letter allowed (`"C"` fails D and F). It also fails when there is no grade or the grade is
Pending, unless `allow_pending` is true (then it is a printed warning). With `grade.archived_unread` not empty (an unread
archived flag could raise the letter) it fails when the letter equals the maximum (`"A"`), else warns. Exit code 2 on policy violation — designed for
CI/CD fail-fast. Without `--policy` or `--policy-preset` the exit code ignores the grade.

## Building

Single binary, no CGo, cross-compiles to all platforms.

```bash
# Prerequisites: Go 1.26+

# Build for current platform
just build                     # → bin/unisupply

# Cross-compile all platforms
just build-all                 # → bin/unisupply-{linux,darwin,windows}-{amd64,arm64}

# Install to GOPATH/bin
just install                   # go install ./cmd/unisupply/

# Or directly
go build -o bin/unisupply ./cmd/unisupply/
```

## Development

```bash
# Build & run
just build                     # compile binary
just run ./                    # scan current project
just run-verbose ./            # scan with verbose output

# Reports
just json ./                   # JSON output
just pdf ./                    # PDF report (needs UNIDOC_LICENSE_API_KEY)
just sbom-cyclonedx ./         # CycloneDX SBOM
just sbom-spdx ./              # SPDX SBOM

# CI/CD scanning
just scan-ci ./                # scan GitHub Actions + build files
just scan-full ./              # all scanners enabled

# Policy enforcement
just policy-strict ./          # strict preset
just policy-moderate ./        # moderate preset
just policy rules.json ./      # custom policy file

# Self-scan (dogfooding)
just self-scan                 # scan unisupply itself
just self-scan-full            # with CI/CD scanning

# Quality
just test                      # run tests
just test-race                 # with race detection
just test-cover                # with coverage report
just lint                      # golangci-lint
just fmt                       # gofmt + goimports
just vet                       # go vet
just check                     # fmt + vet + test
just tidy                      # go mod tidy
just clean                     # remove artifacts
```

## Status

**v0.6.0 — Feature complete.** All 9 scanners, 5 output formats, policy engine, trust index integration, SBOM generation. Production-ready.

## Relationship to UniDoc ecosystem

- **unisupply** — open source supply chain scanner (this project)
- **unitrust** — trust score database backend (sibling project)
- **UniPDF** — used for PDF report generation (dogfooding)
- **UniChart** — used for chart rendering in reports (dogfooding)

unisupply is the free, open-source entry point. It builds credibility and generates leads for UniDoc's enterprise document processing platform.
