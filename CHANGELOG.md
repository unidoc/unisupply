# Changelog

All notable changes to `unisupply` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- Add new entries here as they land on `development`. -->

## [0.5.0] - 2026-06-29

Compliance, hardening, and scoring-accuracy release. The focus is making
unisupply trustworthy to adopt: honest output, safe runtime behavior, and a
documented network contract.

### New Features

- **Reachability-aware vulnerability scoring.** Imported-only CVEs are
  downgraded one severity tier in the project headline; required-only CVEs are
  downgraded two tiers. Per-dep weight multipliers: ×0.7 (imported), ×0.3
  (required). Required-only CVEs no longer promote per-dep `risk_level`.
- **Per-CVE `reachability` field** added to JSON output (`called` / `imported`
  / `required`), enabling downstream tooling to filter by call-path evidence.
- **`owner_verified` UniTrust enrichment.** When `--trust-index-url` is used,
  `owner_verified` in JSON output now reflects UniTrust's curated
  `maintainer_verified`; falls back to GitHub org-type check otherwise.
  Consumers that treated `owner_verified` as a synonym for `is_org` should
  update their logic.
- **Graceful shutdown.** SIGTERM / SIGINT cancel all in-flight scanner requests
  cleanly; no partial output is written on interrupt.
- **GitHub rate-limit handling.** 403 / 429 responses from `api.github.com`
  are treated as transient errors with jittered backoff; scans no longer abort
  on rate-limit bursts.
- **PDF-without-key notice.** When `--format pdf` is used without
  `UNIDOC_LICENSE_API_KEY`, a message is printed to `stderr` naming
  `cloud.unidoc.io` and suggesting `--format text` for fully offline, keyless
  output. The generated PDF will include a watermark without a key.

### Improvements

#### Scoring & output

- Risk headline now uses `max(severity_adjusted, p95_dep_risk, archived_floor,
  cve_floor)` instead of the mean. Projects with reachable CVEs or archived
  deps will see higher scores; clean projects are unaffected.
- Maintainer risk score for a single-maintainer module is reduced 50 → 25 when
  UniTrust has verified the maintainer's identity (`owner_verified: true`).
- Scoring iteration order is now deterministic — `worst_cve_id` is reproducible
  across same-input runs.
- Maintainer scanner activity classification quantized to scan-start UTC day;
  GitHub API responses are disk-cached with a 24h TTL.

#### Safety story & documentation

- **Network transparency contract.** `README.md § Privacy and network access`
  lists every external host unisupply may contact, what is sent, when, and how
  to disable it — including `cloud.unidoc.io` (UniDoc metered license API,
  PDF only). `SECURITY.md` carries a matching summary.
- **EULA disclosure.** `README.md` now prominently notes that `pkg/report/pdf`
  depends on UniPDF (commercial EULA); all other packages are Apache 2.0.
- `go install` path documented in `README.md` with a pinned version example.

#### License compliance

- **`NOTICE` file** with Apache 2.0 §4(d) upstream attributions for `pflag`,
  `x/term`, `x/vuln`, and `yaml.v3`. Added `THIRD_PARTY_LICENSES.md`
  recording the audit date and per-dep findings.
- **License drift CI job** (`license-check`). Runs `go-licenses csv` on every
  PR; fails if any unlisted non-permissive transitive dep appears. `go-licenses`
  is pinned to a known-good commit hash.
- **Bats test suite** for `check-licenses.sh`, covering NOTICE-drift detection.
- **`CODE_OF_CONDUCT.md`** (Contributor Covenant v2.1).

#### Security controls & CI

- **Trust Index SSRF defense.** `--trust-index-url` now requires `https` for
  all non-loopback hosts. RFC1918, link-local (`169.254/16`), and IPv6
  ULA/link-local addresses are rejected at startup unless
  `--trust-index-allow-private` is explicitly set. Resolved IPs are pinned at
  dial time via a custom `DialContext`, preventing DNS-rebinding attacks.
- **CodeQL analysis** workflow (daily schedule + push/PR trigger).
- **Dependabot** configuration for Go modules and GitHub Actions.
- `goimports` pinned to `v0.44.0` in CI (was unpinned, flagged by own CI/CD
  scanner).
- GitHub Actions upgraded to Node 24 runtime.

### Bug Fixes

- Semver comparison bug in the vulnerability finder caused some CVE version
  range checks to be evaluated incorrectly; govulncheck scan failures are now
  surfaced rather than silently dropped.
- Scan output accountability: archived dependency status is now backfilled from
  the maintenance scanner into the per-dep record so text and JSON reports are
  consistent.
- Output accuracy: several per-dep fields (`is_archived`, `is_deprecated`,
  `last_release`) were missing or stale in edge cases; corrected.
- `MaintenanceScanner` error count now displayed as "N of M checked" instead of
  a bare count, preventing confusion when some deps are unreachable.
- Policy conflict: using both `--policy` and `--policy-preset` together now
  prints a clear warning instead of silently preferring one.
- Runtime safety: `govulncheck` scan failures, context cancellations, and
  `go list` errors are propagated as diagnostics rather than swallowed.

### Security Patches

- `golang.org/x/vuln` bumped `v1.3.0 → v1.4.0`.

## [0.4.0] - 2026-05-08

First public release, production-ready for supply chain enforcement in CI/CD pipelines.

### New Features

#### Scanners

- **Vulnerability** — detects known CVEs across all direct and transitive
  dependencies using the Go vulnerability database (`vuln.go.dev`) with
  call-graph-aware reachability via `golang.org/x/vuln`.
- **Maintenance** — flags stale releases (>1 yr, >2 yr), archived repositories,
  and deprecated modules via the Go Module Proxy.
- **Maintainer** — evaluates GitHub contributor activity, bus factor, and
  organization verification status; uses `GITHUB_TOKEN` when present.
- **Typosquatting** — Levenshtein-distance comparison against ~75 well-known
  Go modules with confidence scoring.
- **Resilience** — scores release cadence, governance file presence
  (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`), and
  version-scheme consistency on a 0–100 sub-scale.
- **AI-generated code** — flags modules matching supply-chain-attack patterns:
  very few releases, anonymous single maintainer, generic naming, no governance
  files.
- **CI/CD pipeline audit** — inspects `.github/workflows/*.yml` for unpinned
  action references, over-broad `permissions: write-all`, and secret-exposure
  patterns (`echo $SECRET`, `curl … $TOKEN`).
- **Build file** — detects unpinned Docker `FROM` images (`:latest`, no digest)
  and `curl | bash` / `wget | sh` patterns in `Dockerfile`, `Makefile`, and
  shell scripts.
- **Trust Index** — `--trust-index-url` enriches reports with curated trust
  scores and stewardship data from a
  [unitrust](https://github.com/unidoc/unitrust) instance.

#### Reporting & Policy

- **Weighted composite risk score** — 0–100 per dependency:
  `Vuln×0.40 + Maint×0.25 + Depth×0.15 + Maintainer×0.10 + Maturity×0.10`,
  with typosquat (+0–20), AI-gen (+0–15), and low-resilience (+0–6) penalties.
  Bands: LOW · MEDIUM · HIGH · CRITICAL.
- **Policy engine** — built-in `strict` and `moderate` presets plus custom
  JSON policies (`max_risk_score`, `max_overall_score`, `no_critical_vulns`,
  `no_single_maintainer`, `no_unmaintained_months`, `no_archived`,
  `no_typosquatting`, `max_ci_score`, `blocked_modules`, `allowed_modules`).
  Exits `2` on violation for CI fail-fast.
- **Output formats** — colored terminal text, JSON, enterprise PDF (UniPDF +
  UniChart), CycloneDX 1.5 SBOM, and SPDX 2.3 SBOM.
- **CLI** — `pflag`-based interface with per-scanner toggles, `--min-risk`
  filtering, `--policy` / `--policy-preset`, `--format`, `--output`,
  `--scan-ci`, `--scan-workflows`, and `--verbose`.

### Improvements

#### Release pipeline & security controls

- **Release pipeline** — SSH tag-signature verification against
  `.github/allowed_signers`, version-parity gate, 5-platform cross-compile
  (`linux`, `darwin`, `windows` × `amd64`/`arm64`), `SHA256SUMS`, dual SBOM
  generation, and draft GitHub Release creation on every signed tag push. (#3)
- **Trust anchor** — `.github/allowed_signers` populated with the real
  maintainer SSH signing key; `CODEOWNERS` narrowed to named maintainers so
  any trust-anchor change requires explicit approval. (#14)
- **Weekly security workflow** — `govulncheck`, `gosec`, `unisupply` self-scan
  (moderate preset), and 90-day staleness check; auto-files one GitHub issue
  per ISO week when any gate trips. (#6, #18)
- **SHA-pinned CI actions** — all `actions/*` references pinned to commit SHAs
  so the self-scan does not flag the project's own pipelines. (#6)

#### Code quality & developer experience

- **Centralized version constant** — single source of truth in
  `internal/version`; supports semver lifecycle suffixes (`-dev`, `-alpha.N`,
  `-beta.N`, `-rc.N`) and `ldflags`-injected `Commit` / `BuildDate` at build
  time. (#13)
- **Test coverage** — unit suites for all packages plus an integration suite
  exercising the full scan pipeline against embedded fixture data. (#1, #4, #13)
- **Deterministic SBOM output** — dependency ordering stabilized for
  reproducible builds. (#2)
- **`gosec` static analysis** — added to `golangci-lint`; production file-read
  callsites annotated with justified `#nosec G304`. (#6)
- **Documentation** — `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `RELEASING.md`, and `examples/` with annotated policy files and a ready-to-use
  CI workflow. (#11, #12, #15)

### Bug Fixes

- Fixed `security.yml` gosec step that required GitHub Advanced Security
  (unavailable on public repos); reworked to inline findings. (#8)
- Fixed `git` commands in `security.yml` that failed on the workflow runner. (#9)
- Fixed `verify-version-parity` action grep targets after the version constant
  was moved from `cmd/` and `pkg/report/text.go` to `internal/version`. (#16)

### Security Patches

- Upgraded `golang.org/x/vuln` `v1.1.4` → `v1.3.0` (direct dependency). (#17)
- Upgraded transitive `golang.org/x` dependencies to clear **12 CVEs** reported
  by `govulncheck`: `x/net` `v0.35.0` → `v0.53.0`, `x/crypto` `v0.33.0` →
  `v0.50.0`, `x/image` `v0.24.0` → `v0.39.0`. (#17)
- Self-scan risk score: 26/100 (MEDIUM) → 21/100 (LOW); CVE count: 12 → 0. (#17)
- Policy engine always exits non-zero on violation — never fails silently.
- All GitHub API calls use `GITHUB_TOKEN` when present to prevent
  unauthenticated rate-limit abuse.

[Unreleased]: https://github.com/unidoc/unisupply/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/unidoc/unisupply/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/unidoc/unisupply/releases/tag/v0.4.0
