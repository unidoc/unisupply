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
| AI-generated     | Fresh modules, few releases, generic names                 | Resilience data (module proxy) — **not** offline-capable |
| CI/CD            | Action pinning, permissions, secret exposure               | `.github/workflows/*.{yml,yaml}` |
| Build files      | Unpinned Docker images, `curl \| bash` patterns            | Dockerfile, Makefile, *.sh |
| Trust Index      | Curated trust scores (optional)                            | `unitrust` API             |
| Integrity        | `go.mod` `replace`/`exclude` directive audit, `go.sum` verification, pseudo-version pin audit | `go.mod`/`go.sum` (offline) |

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

### Unavailable axes

An axis whose data could not be collected is dropped from **both** the numerator
and the denominator, and the surviving weights renormalize to sum to 1.0:

```
Risk Score = Σ(measured axis × weight) / Σ(measured weight)  + penalties
```

| Axis | Excludable | Signal that it was unavailable |
|------|-----------|--------------------------------|
| Vulnerabilities (0.40) | yes | `ScoreInput.VulnScanUnavailable` — offline, or govulncheck failed |
| Maintenance (0.25) | yes | no entry in the maintenance map (`ScanAll` inserts only on success) |
| Maintainer Risk (0.10) | yes | `MaintainerInfo.DataAvailable == false` |
| Depth (0.15) | no | derived from the resolved graph |
| Maturity (0.10) | no | derived from the version string |

Because depth and maturity are always available the denominator floors at 0.25.
Each dependency reports `measured_weight` and `excluded_axes` in the JSON
breakdown, and unmeasured component scores serialize as `null` rather than `0` —
a consumer must be able to tell "nothing found" from "nothing looked".

The two alternatives were both rejected: scoring an unmeasured axis as 0 reports
a clean bill of health nobody earned, and scoring it with a hard-coded "unknown"
constant reports a fabricated measurement as a finding.

### Unexamined vs cleared: AI-generated-code detection

Every indicator the AI-gen detector uses derives from the module's first-release
date, which comes from the resilience scanner (module proxy). Without that date
the detector cannot run at all — and the module is **unexamined**, not cleared.

This mattered because both outcomes look identical in the output: a module the
detector skipped and a module it examined and cleared (first released before the
2022-11-01 ChatGPT cutoff) each produce `risk_level: "none"` with score 0, and
`ScanAll` retains only scoring entries. An empty AI-gen result therefore read as
"checked, nothing found" when it often meant "never checked".

`AIGenRisk.data_available` now distinguishes them, and `ScanAll` returns a warning
naming how many modules went unexamined. Offline that is every module, which is
why AI-gen is not among the scanners `--offline` leaves intact.

### Unscored headline

Three of the five headline candidates (`severity_adjusted`, `cve_floor`, and the
fix-age amplifier) are CVE-derived. When the vulnerability scan did not run they
are all structurally 0, so the headline collapses onto `p95_dep_risk` — one
voice of five, deciding alone, on whatever axes survived. Offline that means
dependency-graph position and version scheme.

In that case `overall_risk_level` is `UNKNOWN` and `headline_unscored_reason`
explains why. `overall_risk_score` still carries the computed number for
dashboards and policy gates, labelled indicative in the text and PDF reports.
Per-dependency `risk_level` is unaffected and always carries a real band.

Measured on UniDoc's own libraries, the guard is not hypothetical: without it an
offline scan promoted UniOffice from LOW to MEDIUM on four untagged
pseudo-version transitives, with no CVE check performed.

The headline is also `UNKNOWN` when an **online** scan's govulncheck fails, not
only offline — a failed scan found nothing because it never looked.

**Policy gates deliberately still evaluate the indicative number.** `max_risk_score`
and `max_overall_score` read `OverallScore`/`RiskScore`, which remain populated
when the level is `UNKNOWN`, so the exit-code contract keeps working for CI jobs
that run degraded. This is a deliberate choice, not an oversight: failing a gate
open would be worse than gating on a partial measurement. The preset ceilings
(strict 70/50, moderate 85/70) sit well above the range a degraded scan reaches,
so in practice a scan that measured little will pass the score gates and fail (or
pass) only on the categorical rules. A policy that must not run degraded should
gate on `overall_risk_level != "UNKNOWN"` in the JSON output.

One consequence worth expecting: because per-dependency bands are unchanged, a
degraded scan can report medium-risk dependencies in the summary counts under a
headline that says `UNKNOWN`. The per-dep number describes the measured axes; the
headline withholds a verdict. Both are intentional.

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

### Vulnerability identifiers in report output

Human-facing output — text and PDF — identifies every advisory by its **Go
advisory ID** (`GO-YYYY-NNNN`). That is the only identifier guaranteed to
exist: govulncheck is the scan source, and not every advisory has a CVE (some
carry only a GHSA alias, and fresh Go advisories may carry none at all). A
CVE-first scheme would leave those findings without a name.

CVE and GHSA identifiers are not dropped — they are collected into one place:

- **Text report:** a `VULNERABILITY ID ALIASES` section between the stdlib
  vulnerabilities and the summary.
- **PDF report:** an "Appendix: Vulnerability ID Aliases" table.

Advisories with no aliases are omitted from both, and the section disappears
entirely when nothing in the report has an alias.

CVE stays load-bearing internally: EPSS and KEV lookups are keyed by CVE ID
(see below), and JSON output is unchanged — its per-vulnerability `aliases`
array carries the full list, because it is the machine contract.

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
| Local-path            | Replacement path is a filesystem path — relative, absolute, UNC, or drive-letter; both Unix and Windows syntaxes are recognized regardless of host OS | MEDIUM   | +8 per-dependency penalty                         |
| Major-version redirect | Replacement path is the original module gaining or swapping a `/vN` (N ≥ 2) semantic-import-versioning suffix (same underlying module) | MEDIUM   | +8 per-dependency penalty                         |
| Redirect              | Replacement path points to a genuinely different module                                         | HIGH     | +20 per-dependency penalty; floors the project headline to HIGH (51, or 60 for a direct dependency) |

Every `exclude` directive renders as an INFO finding for transparency — it
carries no score effect. A dependency with an applicable replace directive
gets the `replaced` risk factor regardless of class; only MEDIUM/HIGH classes
add to the score. A version-scoped replace (`replace A v1.2.3 => …`) only
marks the dependency as replaced when the selected version matches; the
directive itself still appears as a finding, annotated with the version it
applies to.

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

### go.sum verification

The Integrity scanner also audits `go.sum`:

| Finding            | Condition                                                                    | Severity | Headline effect                      |
| ------------------ | ---------------------------------------------------------------------------- | -------- | ------------------------------------ |
| `gosum_missing`    | `go.mod` declares requirements but no `go.sum` exists                        | HIGH     | None — noise-rule exempt             |
| `gosum_incomplete` | A direct (non-replaced) dependency's resolved version has no `go.sum` entry  | MEDIUM   | None — noise-rule exempt             |
| `gosum_mismatch`   | `go mod verify` reports a checksum mismatch (local module cache does not match `go.sum`) | CRITICAL | Floors the headline to CRITICAL (76) |

The completeness check covers **direct dependencies only** — under Go 1.17+
module graph pruning, transitive modules listed by `go mod graph` can
legitimately have no `go.sum` entry, so a full-graph join would over-report.
A direct requirement is always an MVS root whose `go.mod` hash must be
recorded; its absence is a real gap. The check is skipped entirely when
`vendor/modules.txt` is present — builds with `-mod=vendor` do not consult
`go.sum`.

Go.sum verification **shells out to `go mod verify`**, which checks the local
module cache against the checksums already pinned in `go.sum` and honors
`GOPRIVATE`/`GONOSUMDB` itself. It does **not** contact the checksum database
(`sum.golang.org`) or perform transparency-log lookups — those happen at
download time via the toolchain's own sumdb client; this check detects
post-download tampering of the cache or of `go.sum`. The outcome is reported
as `gosum_verified` in all output formats with four honest states: `"true"`
(verified), `"false"` (confirmed mismatch), `"offline"` (verification skipped
in offline mode), and `"skipped"` (no `go.sum`, the `go` toolchain could not
be run, the scan was cancelled, or verify failed for a non-integrity reason
such as a cold module cache with no network). A non-zero exit is only treated
as a mismatch when the output carries an actual integrity marker
(`has been modified`, `checksum mismatch`, `SECURITY ERROR`). Only a confirmed
mismatch floors the headline or fails the `require_gosum_verified` policy rule
(on by default in the strict preset) — UNKNOWN states are never treated as
failures.

Note a toolchain subtlety: `go mod verify` re-checks each module's `go.mod`
hash against `go.sum` when loading the build list, but verifies module zips
against the cache's own integrity records — so `gosum_verified: "true"` means
the build graph's checksums are consistent, not that every archive byte was
re-hashed against `go.sum`.

### Pseudo-version pins

The Integrity scanner also flags every resolved dependency whose **pinned**
`go.mod` version is a pseudo-version (`v0.0.0-YYYYMMDDHHMMSS-abcdefabcdef`,
including the "pseudo-version on top of a tag" form
`v0.4.1-0.20220921163831-...`), using
`golang.org/x/mod/module.IsPseudoVersion` — no custom regex.

| Condition                                     | Severity | Score effect                    |
| ---------------------------------------------- | -------- | -------------------------------- |
| Direct dependency, not test-only               | MEDIUM   | +4 per-dependency penalty         |
| Transitive dependency, not test-only           | LOW      | +2 per-dependency penalty         |
| Confirmed test-only (`IsTestOnly == &true`)     | INFO     | None — surfaced for transparency  |

An unknown test-only classification (`IsTestOnly == nil`) is treated as
**not** test-only, consistent with the scorer's general convention of
under-discounting rather than silently applying a discount on unverified
data.

This is a **distinct signal** from the AI-generated-code scanner's
`pseudo_version_only` indicator (see above): that indicator fires when a
module has **zero tagged releases ever** — a historical property of the
module proxy's published version list (`ResilienceInfo.VersionScheme ==
"pseudo" && TotalReleases == 0`). The integrity check here fires on the
version **currently pinned** in `go.mod`, which can happen even for a module
with real tagged releases (e.g. pinned to a commit between tags). A
dependency can trigger both signals at once, and the two contributions are
additive: the `pseudo_version_only` indicator adds 10 to the aigen score,
i.e. 1.5 points here (10 × 0.15), and the pseudo-version bonus adds at most 4
— so the pseudo-version-related contributions sum to at most 5.5, which alone
cannot promote a dependency into the HIGH band. Note this is not an enforced
cap: the aigen bonus as a whole can reach 15 when other aigen indicators fire
alongside `pseudo_version_only`.

Pseudo-version pins are **per-dependency risk factors only** — they do not
feed the `integrity_floor` headline candidate and cannot, on their own, push
a project's overall score into the HIGH band. This is deliberate: routine
pins such as `golang.org/x/telemetry` (which has no tagged releases) are
common in the Go ecosystem and must not push projects to HIGH.

Enable the `forbid_pseudo_versions` policy rule (on by default in the strict
preset) to fail CI on any non-test-only pseudo-version pin. Unlike
`forbid_replace_redirect`, this rule **does** exempt confirmed test-only
dependencies — a pseudo-version pin is a provenance/pinning-hygiene signal,
not a hijack vector, so test-time exposure to CI secrets is not the relevant
threat model here.

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
