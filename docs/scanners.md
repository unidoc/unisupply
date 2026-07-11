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
| CI/CD            | Action pinning, permissions, secret exposure               | `.github/workflows/*.{yml,yaml}` |
| Build files      | Unpinned Docker images, `curl \| bash` patterns            | Dockerfile, Makefile, *.sh |
| Trust Index      | Curated trust scores (optional)                            | `unitrust` API             |
| Integrity        | `go.mod` `replace`/`exclude` directive audit               | `go.mod` (offline)          |

The CI/CD and Build-files scanners are off by default; enable them with
`--scan-workflows` (workflow files `*.yml` and `*.yaml` only) or `--scan-ci`
(workflows + Dockerfile + Makefile + shell scripts). The Trust Index scanner
activates when `--trust-index-url` is supplied.

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
  + Replace Penalty        (0–20)  // 20 for a redirect replace, 8 for a local-path replace, 0 for a version-pin
```

Weights are defined in `pkg/scorer/risk.go` (`Weight*` constants). The final
value is rounded and clamped to `[0, 100]`.

### Vulnerability reachability

`unisupply` inherits govulncheck's call-graph analysis and classifies each
finding into one of three reachability tiers based on how deeply the vulnerable
symbol appears in the trace. The govulncheck
[`Frame`](https://pkg.go.dev/golang.org/x/vuln/internal/govulncheck) struct
models each step in a call trace as `{Module}`, `{Module, Package}`, or
`{Module, Package, Function}` — the reachability tier reflects which fields are
populated:

| Tier       | Meaning                                                                                   |
| ---------- | ----------------------------------------------------------------------------------------- |
| `called`   | The vulnerable function appears at the end of a resolved call-graph path — `{module, package, function}` all present. |
| `imported` | The vulnerable package is imported by a package in your build, but no call path to the vulnerable function was found — `{module, package}` present, no `function`. |
| `required` | The module containing the vulnerability is required by your module graph, but no package from it is imported in the build — `{module}` only. |

An absent `reachability` field (empty string) on a finding that did not come
from govulncheck is treated as `called` for scoring purposes — it is the most
conservative default.

#### Scoring effect

Reachability adjusts the vulnerability contribution at two levels:

**Project-level headline** (`severityAdjustedVulnScore`): the worst observed
CVE severity is downgraded before computing the headline score —
- `imported`: the worst CVE's severity tier is dropped one level
  (CRITICAL → HIGH, HIGH → MEDIUM, MEDIUM → LOW).
- `required`: the worst CVE's severity tier is dropped two levels
  (CRITICAL → MEDIUM, HIGH → LOW, MEDIUM → LOW).

This downgrade is applied first; the existing test-only downgrade is applied on
top of it.

**Per-dependency weight multiplier** (inside `vulnScore`): each CVE's raw
severity weight is scaled by a reachability factor before accumulation —
- `called` (or absent): ×1.0 — full weight.
- `imported`: ×0.7 — moderate discount.
- `required`: ×0.3 — heavy discount.

**Severity floor and level promotion**: a `required`-only CVE does **not**
raise the per-dependency `risk_level` to HIGH (no floor of 51), and does not
count toward the HIGH-and-above promotion logic. A `called` or `imported`
CRITICAL or HIGH CVE still triggers the HIGH floor (score ≥ 51).

#### Static-analysis caveat

> **Important:** "not called" does NOT mean "not exploitable."

Go's call-graph analysis — and therefore govulncheck's reachability
classification — cannot follow:

- **Reflection** (`reflect.Value.Call`, `reflect.Method`, dynamic dispatch
  through `interface{}` values whose concrete type is not statically known).
- **Plugin loading** (`plugin.Open` — loaded symbols are invisible to the
  static analyzer).
- **Runtime type dispatch** through opaque interfaces: if a call goes through
  an interface whose concrete implementor is only known at runtime, the edge
  may be missing from the graph.
- **Build-tag-gated code** not compiled during the analysis build: a
  `//go:build linux` file is skipped on a macOS CI runner.
- **Code generated at build time** (protobuf stubs, mock generators, etc.) that
  is not present when the analyzer runs.
- **Indirect calls through `interface{}` boundaries** where type information
  is erased.

Treat reachability as a **confidence calibrator**, not a filter. A finding
classified `imported` or `required` is *less likely* to be on a hot exploit
path, but it is not proven safe. For projects that use heavy reflection
frameworks (dependency injection containers, ORMs, RPC stubs) or load plugins
at runtime, `imported`-only findings should be weighted as if they were
`called`.

See the upstream documentation for further precision-limit details:
[Go Vulnerability Management](https://go.dev/security/vuln/) ·
[govulncheck reference](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).

### Threat-intel enrichment (EPSS + CISA KEV)

Every CVE is enriched with two real-world exploitation signals:

| Source | Field(s) | Endpoint | Meaning |
| ------ | -------- | -------- | ------- |
| [FIRST.org EPSS](https://www.first.org/epss/) | `epss_score`, `epss_percentile`, `epss_date` | `api.first.org` | Estimated probability (0.0–1.0) that the CVE will be exploited within the next 30 days. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `in_kev`, `kev_date_added`, `kev_known_ransomware` | `www.cisa.gov` | The CVE is confirmed exploited in the wild by CISA. |

Both are keyed by CVE ID: for `GO-*`/`GHSA-*` vulns the first `CVE-*` alias
is used. Vulnerabilities without a CVE alias (common for fresh Go advisories)
have no threat-intel data — that is expected, not an error.

**Field-presence semantics.** `epss_score` absent means EPSS has no score for
that CVE (a normal gap — EPSS does not score every CVE), the lookup failed, or
no CVE alias exists; a present `0.0` is a real score. `in_kev` absent means
"not checked" (KEV fetch failed or no CVE alias); `false` means "checked and
not listed".

#### Scoring effect

Order of operations inside the project-level headline
(`severityAdjustedVulnScore`), per CVE:

1. Normalise severity (`effectiveTier`; UNKNOWN + confirmed-called → HIGH).
2. Reachability downgrade (`imported` −1 tier, `required` −2 tiers).
3. Test-only downgrade (−1 tier when the dep is confirmed test-only).
4. **EPSS amplifier** — `epss_score ≥ 0.5` and tier below CRITICAL: promote
   one tier (LOW → MEDIUM, MEDIUM → HIGH, HIGH → CRITICAL).
5. **KEV override** — `in_kev` true: force CRITICAL.
6. Step function counts the resulting tier.

The threat-intel rules apply **after** the downgrades because the downgrades
encode "this code path isn't reachable in this project" — wild-exploitation
status doesn't make an unreachable path more vulnerable. The most
counter-intuitive consequence: **a downgrade-dropped CVE is not resurrected.**
Once the reachability or test-only downgrade removes a CVE from the step
function (e.g. a test-only LOW), neither EPSS nor KEV brings it back. Instead,
a **hidden-risk warning** is emitted whenever a KEV-listed CVE (or one with
EPSS ≥ 0.9) was downgraded: static analysis says the path isn't reachable, but
the exploitation evidence warrants manual review.

Per-dependency effects:

- `vulnScore` gains an additive bonus of `max_epss_on_dep × 15`, capped at the
  existing 100 ceiling (a dep with one EPSS-0.8 CVE gains +12).
- Any KEV-listed CVE floors the dep at **76 (CRITICAL)** regardless of
  severity and reachability — presence on KEV essentially mandates patching.
- Any KEV-listed CVE also produces a `kev` TIME-BOMB entry in the report.

The 0.5 EPSS threshold means FIRST.org estimates >50% exploitation likelihood
within 30 days; promotion is bounded at one tier. KEV is binary and absolute.
Neither threshold is operator-tunable — one default, documented rationale.

#### Cache and failure behavior

EPSS responses are cached per CVE under `$XDG_CACHE_HOME/unisupply/epss/` and
the KEV catalog (single ~1.5 MB bulk fetch per scan) under
`$XDG_CACHE_HOME/unisupply/kev/`, both with a 24-hour TTL (EPSS scores are
recomputed daily; KEV updates weekly at most). Both lookups are best-effort:
on failure the scan completes with a warning and the fields absent —
threat-intel unavailability never fails a scan.

> **Coverage caveat:** EPSS and KEV apply per-CVE; they do not change which
> CVEs are detected. Coverage is bounded by govulncheck + OSV enrichment, and
> the same static-analysis limits described above apply.

### Vulnerability floor

Any dependency with at least one `called` or `imported` CVE has its score
floored to **51** (HIGH). The rationale lives in `pkg/scorer/risk.go`:

> A known CVE with a fix available is actionable and must not be buried in
> MEDIUM/LOW where it looks safe.

`required`-only CVEs do not trigger this floor — the module is in the graph
but no package from it is compiled into your binary.

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

## Integrity

The Integrity scanner audits `go.mod` `replace` and `exclude` directives —
pure offline analysis, no network calls. Every `replace` directive is
classified by comparing the replacement module path against the original:

| Class                 | Condition                                                                                     | Severity | Score effect                                    |
| --------------------- | ---------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------ |
| Version-pin           | Replacement path equals the original path                                                       | LOW      | None — expected, pins a specific version          |
| Local-path            | Replacement path has a `./`/`../` prefix, or is an OS-absolute filesystem path                   | MEDIUM   | +8 per-dependency penalty                         |
| Major-version redirect | Replacement path is the original module gaining or swapping a `/vN` (N ≥ 2) semantic-import-versioning suffix (same underlying module) | MEDIUM   | +8 per-dependency penalty                         |
| Redirect              | Replacement path points to a genuinely different module                                         | HIGH     | +20 per-dependency penalty; floors the project headline to HIGH (51, or 60 for a direct dependency) |

Every `exclude` directive renders as an INFO finding for transparency — it
carries no score effect. A dependency with any replace directive gets the
`replaced` risk factor regardless of class; only MEDIUM/HIGH classes add to
the score.

A HIGH-severity (redirect) replace on a non-test-only dependency is the
`integrity_floor` headline candidate — it floors the project's overall score
into the HIGH band even when no other signal would. LOW and MEDIUM replace
classes never move the headline; this is deliberate — version pins, local
development overrides, and same-module major-version redirects are common and
must not trigger noisy false alarms.

Enable the `forbid_replace_redirect` policy rule (on by default in the strict
preset) to fail CI when a redirect replace is present. Note the deliberate
asymmetry with the headline: the `integrity_floor` headline candidate skips
test-only dependencies, but the `forbid_replace_redirect` policy rule does
not — test-time code still executes in CI (with access to CI secrets), so a
hijacked test-only dependency is not a safe blind spot for policy purposes.

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
