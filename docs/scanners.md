# Scanners and Risk Scoring

This document describes the scanners `unisupply` runs and the exact formula used
to combine their results into a 0–100 risk score per dependency. It is the
canonical reference for the algorithm; if the code in `pkg/scorer/risk.go` and
this document disagree, the code wins — please open a PR fixing this file.

## Scanners

| Scanner          | What it checks                                             | Data source                |
| ---------------- | ---------------------------------------------------------- | -------------------------- |
| Vulnerability    | Known CVEs (call-graph-aware via `govulncheck`)            | Go vuln DB (vuln.go.dev)   |
| Maintenance      | Last release, archive status, deprecation                  | Go Module Proxy            |
| Maintainer       | Contributors, bus factor, activity, org verification       | GitHub API                 |
| Typosquatting    | Levenshtein-similarity to ~75 well-known modules           | Built-in list              |
| Resilience       | Release cadence, governance files, version-scheme          | GitHub API                 |
| AI-generated     | Fresh modules, few releases, generic names                 | Module metadata heuristics |
| CI/CD            | Action pinning, permissions, secret exposure               | `.github/workflows/*.yml`  |
| Build files      | Unpinned Docker images, `curl \| bash` patterns            | Dockerfile, Makefile, *.sh |
| Trust Index      | Curated trust scores (optional)                            | `unitrust` API             |

The CI/CD and Build-files scanners are off by default; enable them with
`--scan-workflows` (workflows only) or `--scan-ci` (workflows + Dockerfile +
Makefile + shell scripts). The Trust Index scanner activates when
`--trust-index-url` is supplied.

## Risk score

For each dependency, `unisupply` computes:

```
Risk Score (0–100) =
    Vulnerabilities × 0.40
  + Maintenance     × 0.25
  + Depth           × 0.15
  + Maintainer Risk × 0.10
  + Maturity        × 0.10
  + Typosquat Penalty      (0–20)  // typosquat.Confidence × 20
  + AI-Gen Penalty         (0–15)  // aiGenRisk.Score × 0.15
  + Low-Resilience Penalty (0–6)   // (30 − resilience.Score) × 0.2 when score < 30
```

Weights are defined in `pkg/scorer/risk.go` (`Weight*` constants). The final
value is rounded and clamped to `[0, 100]`.

### Vulnerability floor

Any dependency with at least one known CVE has its score floored to **51**
(HIGH). The rationale lives in `pkg/scorer/risk.go`:

> A known CVE with a fix available is actionable and must not be buried in
> MEDIUM/LOW where it looks safe.

### Component scoring

| Component        | Range  | Notes                                                          |
| ---------------- | ------ | -------------------------------------------------------------- |
| Vulnerabilities  | 0–100  | CRITICAL = 100, HIGH = 80, MEDIUM = 50, LOW = 25; capped at 100 |
| Maintenance      | 0–100  | 0 (<6 mo), 25 (<12 mo), 60 (<24 mo), 90 (≥24 mo); 100 if archived; 30 if unknown |
| Depth            | 0–100  | 0 (direct), 20 (depth 1), 40 (deeper)                          |
| Maintainer       | 0–100  | 0 for trusted namespaces / multi-maintainer; 50 for bus factor 1; 30 if unknown |
| Maturity         | 0–100  | 0 for trusted namespaces or v1+; 30 for v0.x; 50 if untagged   |

The maintainer and maturity components fall back to **0** for trusted
namespaces (`golang.org/x/`, `google.golang.org/`, `k8s.io/`,
`go.opentelemetry.io/`, `github.com/golang/`, `github.com/google/`,
`github.com/googleapis/`, etc.) — these projects use v0.x and centralized
maintainership by design, not neglect.

## Risk bands

| Level    | Score   |
| -------- | ------- |
| LOW      | 0–25    |
| MEDIUM   | 26–50   |
| HIGH     | 51–75   |
| CRITICAL | 76–100  |

## Overall project score

The project-level score in the report header is computed in
`computeOverallScore` from the per-dependency scores. See
`pkg/scorer/risk.go` for the exact aggregation.
