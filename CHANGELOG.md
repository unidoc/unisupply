# Changelog

All notable changes to `unisupply` are documented in this file.

The format is based on [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- Add new entries here as they land on `development`. -->

## [0.4.0] - YYYY-MM-DD

<!-- release date filled in by PR of rc-v* -->

First public release. Feature-complete: nine scanners, five output formats,
policy engine, Trust Index integration, SBOM generation.

### Added

- **Vulnerability scanner** — queries the Go vulnerability database
  (`vuln.go.dev`) for known CVEs across all direct and transitive dependencies.
- **Maintenance scanner** — flags stale releases, archived repositories, and
  deprecated modules using the Go Module Proxy.
- **Maintainer scanner** — analyzes GitHub contributor activity, bus factor,
  and organization verification status.
- **Typosquatting detector** — Levenshtein-distance comparison against a
  built-in list of ~75 well-known modules.
- **Resilience scanner** — release cadence, governance files, version-scheme
  consistency.
- **AI-generated code heuristics** — flags freshly published modules with few
  releases and generic names.
- **CI/CD pipeline audit** — checks `.github/workflows/*.yml` for unpinned
  actions, over-broad permissions, and secret-exposure patterns.
- **Build file scanner** — detects unpinned Docker base images and
  `curl | bash` patterns in Dockerfile / Makefile / shell scripts.
- **Trust Index integration** — optional `--trust-index-url` flag enriches
  reports with curated trust scores from a [unitrust](https://github.com/unidoc/unitrust)
  instance.
- **Risk scoring** — weighted composite score (0–100) per dependency with
  LOW / MEDIUM / HIGH / CRITICAL bands.
- **Policy engine** — `strict` and `moderate` built-in presets plus
  fully-configurable JSON policy files; exits `2` on violation for CI
  fail-fast.
- **Output formats** — colored terminal text, JSON, enterprise PDF report
  (built with UniPDF + UniChart), CycloneDX 1.5 SBOM, SPDX 2.3 SBOM.
- **CLI surface** — `pflag`-based interface with per-scanner toggles, risk
  filtering (`--min-risk`), and verbose per-dependency breakdowns.

### Security

- All maintainer / resilience scans use `GITHUB_TOKEN` when present to avoid
  unauthenticated rate-limit thrashing.
- The CI/CD scanner refuses to follow symlinks out of the workflow directory.
- Policy violations fail closed (non-zero exit), never silently.

[Unreleased]: https://github.com/unidoc/unisupply/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/unidoc/unisupply/releases/tag/v0.4.0
