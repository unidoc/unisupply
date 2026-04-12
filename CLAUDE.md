# UniDoc Supply Chain Security — Developer Guide

## What is this?

An open-source CLI tool that **analyzes Go module dependency chains and produces supply chain risk assessment reports**. It scans for vulnerabilities, evaluates maintainer health, detects typosquatting, flags AI-generated code risks, audits CI/CD pipelines, and generates enterprise-grade PDF reports.

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
  │   ├── AI-generated code risk
  │   ├── CI/CD pipeline audit
  │   ├── Trust Index lookup (unitrust)
  │   └── Build file scanning
  ├── Compute risk scores             pkg/scorer/
  ├── Evaluate org policies           pkg/policy/
  └── Generate reports                pkg/report/
      ├── Text (colored terminal)
      ├── JSON (machine-readable)
      ├── PDF (enterprise, UniPDF)
      └── SBOM (CycloneDX, SPDX)
```

## Risk Scoring

```
Risk Score (0-100) =
    Vulnerabilities × 0.40
  + Maintenance     × 0.25
  + Depth           × 0.15
  + Maintainer Risk × 0.10
  + Maturity        × 0.10
  + Typosquat Bonus (0-20)
  + AIGen Bonus     (0-15)
  - Resilience      (0-6)
```

Levels: LOW (0-25), MEDIUM (26-50), HIGH (51-75), CRITICAL (76-100)

## The 9 Scanners

| Scanner | What it checks | Data source |
|---------|---------------|-------------|
| **Vulnerability** | Known CVEs in dependencies | Go vuln DB (vuln.go.dev) |
| **Maintenance** | Last release, archive status, deprecation | Go Module Proxy |
| **Maintainer** | Contributors, bus factor, activity, org verification | GitHub API |
| **Typosquatting** | Similar names to well-known packages (Levenshtein) | Built-in list (~75 modules) |
| **Resilience** | Release cadence, governance files, version scheme | GitHub API |
| **AI-Generated** | Fresh modules, few releases, generic names | Heuristics |
| **CI/CD** | Action pinning, permissions, secret exposure | .github/workflows/*.yml |
| **Build Files** | Unpinned Docker images, curl\|bash patterns | Dockerfile, Makefile, *.sh |
| **Trust Index** | Package trust scores from curated database | unitrust API |

## Integration with unitrust

unisupply optionally queries the [unitrust](../unitrust/) Trust Index API:

```bash
unisupply --trust-index-url http://localhost:8080 ./
```

This calls `POST /api/v1/lookup` with all discovered modules and enriches the report with curated trust scores, maintainer verification, and stewardship data.

## Tech stack

- Go 1.25.3, no CGo
- `github.com/spf13/pflag` — CLI flags
- `github.com/unidoc/unipdf/v3` — PDF report generation (dogfooding)
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
| `pkg/scanner/aigen.go` | AI-generated code detection |
| `pkg/scanner/ci.go` | CI/CD pipeline audit |
| `pkg/scanner/buildfiles.go` | Dockerfile/Makefile scanning |
| `pkg/scanner/trustindex.go` | unitrust API integration |
| `pkg/scorer/risk.go` | Risk score computation |
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
unisupply ./ --policy strict
unisupply ./ --policy-file ./my-policy.json

# Filter output
unisupply ./ --min-risk medium --show-only vulnerabilities,maintenance
```

### Environment variables

| Var | Purpose |
|-----|---------|
| `GITHUB_TOKEN` | GitHub API access (higher rate limits, private repos) |
| `UNIDOC_API_KEY` | UniDoc license key (for PDF generation) |

## Policy engine

Built-in presets: `strict`, `moderate`. Or custom JSON:

```json
{
  "max_critical": 0,
  "max_high": 5,
  "max_vulnerability_age_days": 30,
  "require_pinned_actions": true,
  "blocked_modules": ["github.com/suspicious/pkg"],
  "whitelisted_modules": ["golang.org/x/*"]
}
```

Exit code 2 on policy violation — designed for CI/CD fail-fast.

## Building

Single binary, no CGo, cross-compiles to all platforms.

```bash
# Prerequisites: Go 1.25+

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
just pdf ./                    # PDF report (needs UNIDOC_API_KEY)
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

**v0.4.0 — Feature complete.** All 9 scanners, 4 output formats, policy engine, trust index integration, SBOM generation. Production-ready.

## Relationship to UniDoc ecosystem

- **unisupply** — open source supply chain scanner (this project)
- **unitrust** — trust score database backend (sibling project)
- **UniPDF** — used for PDF report generation (dogfooding)
- **UniChart** — used for chart rendering in reports (dogfooding)

unisupply is the free, open-source entry point. It builds credibility and generates leads for UniDoc's enterprise document processing platform.
