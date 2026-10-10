# Scanners and Risk Scoring

This document describes the scanners `unisupply` runs and the exact formula used
to combine their results into a 0–100 risk score per dependency. It is the
canonical reference for the algorithm; if the code in `pkg/scorer/risk.go` and
this document disagree, the code wins — please open a PR fixing this file.

## Scanners

| Scanner          | What it checks                                             | Data source                |
| ---------------- | ---------------------------------------------------------- | -------------------------- |
| Vulnerability    | Known CVEs (call-graph-aware via `govulncheck`)            | Go vuln DB (vuln.go.dev)   |
| Maintenance      | Last release, default-branch activity, archive status, deprecation | Go Module Proxy (GitHub commits API as a fallback) |
| Maintainer       | Contributors, bus factor, activity, org verification       | GitHub API                 |
| Typosquatting    | Levenshtein-similarity to ~75 well-known modules           | Built-in list              |
| Resilience       | Release cadence, governance files, version-scheme          | GitHub API                 |
| AI-generated     | Fresh modules, few releases, generic names                 | Resilience data (module proxy) — **not** offline-capable |
| CI/CD            | Action pinning, permissions, secret exposure               | `.github/workflows/*.{yml,yaml}` |
| Build files      | Unpinned Docker images, `curl \| bash` patterns            | Dockerfile, Makefile, *.sh |
| Trust Index      | Curated trust scores (optional)                            | `unitrust` API             |
| Integrity        | `go.mod` `replace`/`exclude` directive audit, `go.sum` verification, pseudo-version pin audit | `go.mod`/`go.sum` (offline) |

A repository that GitHub has renamed or transferred answers with a redirect.
The Maintainer scanner follows one hop, on `api.github.com` only, and reports
the repository under its canonical name; any other redirect target is treated
as an error. When maintainer data cannot be collected, the scan warning names
the cause: an unauthenticated or rate-limited GitHub API, or an API error.

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

For `called` findings the JSON report also carries `call_path`: one example
path from the project's code to the vulnerable function, outermost frame first,
for example `example.com/app/cmd/app.main`, then
`golang.org/x/net/http2.Server.ServeConn`. It keeps the entry frame, the frame
where each run of same-package frames hands over to the next package, and the
vulnerable function, at most 8 entries; `"..."` marks where a longer path was
cut, so consecutive entries are not necessarily direct callers. A path need not
start at `main`: govulncheck also treats the exported functions of library
packages as entry points. When a vulnerability has several vulnerable symbols
the shortest path is kept (ties broken alphabetically), so the choice does not
depend on govulncheck's output order. The path is evidence that the code is on
an execution path, not proof that the vulnerability is exploitable (see the
caveat below).

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
(see below), and JSON output is unchanged by this convention — its
per-vulnerability `aliases` array carries the full list, because it is the
machine contract.

**Repeated enrichment failures are collapsed.** When several advisories fail
severity enrichment, the per-advisory `severity lookup failed …` warnings
(and, separately, the `severity not yet published …` warnings for unscored
advisories) render as one line each naming the count and the first five IDs (each advisory once,
even when reported under more than one module). The collapse happens in the
scanner, so the summary is what the top-level `warnings` array in JSON output
contains as well; the per-vulnerability `enrichment_errors` array is not
collapsed and remains the machine contract for which advisories failed.

### Severity resolution order

govulncheck does not report a severity, and OSV's `GO-` records never carry
one, so each advisory with an unknown severity is resolved in this order, and
the first tier that yields a severity wins:

1. OSV record of the advisory's own ID.
2. OSV records of its `GHSA-*` aliases, then its `CVE-*` aliases, each group in
   ascending order, at most 4 alias lookups per advisory. When the advisory has
   a CVE alias, one of the 4 is kept for it, so GHSA aliases cannot crowd it
   out. Only the aliases already on the advisory are looked up; aliases listed
   inside fetched records are not followed. A record's `database_specific.severity` is preferred; if
   absent, its CVSS v3.0/v3.1 vector is scored locally with the first.org base
   score formula. CVSS v2 and v4 entries are ignored, and a score of 0.0 is not
   treated as a severity.
3. NVD (by CVE alias).
4. The GitHub Advisory API (by CVE alias).

OSV alias responses are cached for 24 hours, one file per alias, so advisories
that share an alias cost one request.

When an advisory is resolved from an alias record, the JSON field
`severity_alias` names that alias and `severity_source` is `osv`.

**`severity_source: "unscored"` is not a failure.** It means every source
consulted for the advisory answered and none has published a severity: OSV
with 200 or 404, and NVD and GitHub (when a CVE alias exists) with 200.
`severity` stays `UNKNOWN`, `enrichment_failed` is false and
`enrichment_errors` is empty. Compare `severity_source: "none"` with
`enrichment_failed: true`, which means at least one lookup failed (network
error, rate limiting such as NVD 429 or GitHub 403, HTTP 5xx, unparsable
response). A failed lookup may have missed a published severity, so it is
never reported as unscored. Scoring is the same for both: an
unscored advisory is treated as MEDIUM, or HIGH when the vulnerable function is
confirmed called. Only the label differs; the text report marks the two cases
`[enrichment_failed]` and `[severity_unpublished]`, and the PDF lists unscored
advisories in a separate Data-quality note. Unscored advisories are rechecked
after one hour.

**NVD API key.** NVD allows 5 requests per rolling 30 seconds without a key and
50 with one. Set `--nvd-api-key` (or `NVD_API_KEY`) to make the NVD fallback
less likely to be rate limited. The key is sent only as an `apiKey` header to
`services.nvd.nist.gov`, never in a URL, report, warning, cache file or
`--network-log` line. Surrounding whitespace is trimmed from the key. NVD
answers an invalid key with HTTP 404 and the header `message: Invalid apiKey.`;
on that answer, or on HTTP 401, one warning is emitted, that request is retried
without the key and the rest of the scan queries NVD unauthenticated, exactly
as if no key had been set. A 403 or a 404 without that message is an ordinary
failed lookup and the key is kept, since a 403 can come from NVD's CDN under
load. A key containing characters an HTTP header cannot carry is dropped the
same way, with one warning. Prefer `NVD_API_KEY` over the flag: a flag value is
visible to other users in `ps` and can end up in CI logs. The lookup order is
unchanged.

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
3. Test-only downgrade (−1 tier when the dep is confirmed test-only). Outside-the-build
   status adds nothing here: the reachability tier in step 2 already encodes
   "not linked in" (see [Build membership](#build-membership)).
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
| Maintenance      | 0–100  | 0 (<6 mo), 25 (<12 mo), 60 (<24 mo), 90 (≥24 mo), on the newer of the last release and the default branch's last commit; 100 if archived or deprecated; 30 if unknown |
| Depth            | 0–100  | 0 (direct), 20 (depth 1), 40 (deeper)                          |
| Maintainer       | 0–100  | 0 for trusted namespaces / multi-maintainer; 50 for bus factor 1; 30 if unknown |
| Maturity         | 0–100  | 0 for trusted namespaces or v1+; 30 for v0.x; 50 if untagged   |

### Maintenance age and deprecation

The Maintenance axis does not rest on release tags alone. A repository that is
worked on but rarely tagged would otherwise read as abandoned, so the axis
bands on the newer of two dates:

- **Last release:** the latest version's time from the module proxy
  (`months_since_release`).
- **Last commit on the default branch:** the module proxy resolves a branch
  query, `proxy.golang.org/<module>/@v/<branch>.info`, to the branch head's
  commit time. That needs no token and no GitHub quota, and works for modules
  not hosted on GitHub. The branch is the repository's GitHub `default_branch`
  when the maintainer scan has it, otherwise `main`, then `master`. The `HEAD`
  query is deliberately not used: the proxy can serve it stale by months.

  Any commit on the default branch counts: there is no filtering of bot or
  CI-only commits yet, so a single workflow edit makes the date recent. For a
  module in a multi-module repository (for example
  `github.com/aws/aws-sdk-go-v2/service/s3`) the date is the repository's last
  commit on that branch, not the last commit under the module's directory.

"No such branch" is a 404 or 410 whose body says so: `unknown revision`, or
`invalid version:` (the revision is missing, or it does not hold this module).
A 404 or 410 with that answer on every branch leaves activity unknown without a
fallback: for a module such as `foo/v2` whose default branch has moved to v3,
the repository's latest commit would describe a different module.

Any other failure is transient: a 5xx, a query that runs past its own
10-second timeout (or the `--timeout`, if shorter), or the proxy's
`not found: fetch timed out` 404, which it sends when its own fetch of a cold
repository gives up and then repeats for a while. On a transient failure with a
GitHub token set, the GitHub commits API
(`/repos/{owner}/{repo}/commits?per_page=1`, which lists the default branch) is
asked instead; without a token, or if that fails too, the module is counted in
a scan warning. Without activity the axis uses the release age alone, as
before; archived modules are not looked up.

A resolved branch answer, and the latest version's `go.mod` (read for
deprecation), are kept in the on-disk cache for 24 hours, like the GitHub API
responses, so a rerun within the day does not ask again.

The JSON `maintenance` object reports `last_activity`, `months_since_activity`,
`activity_source` (`proxy_branch` or `github_commits`) and `activity_branch`
when activity is known; the text and PDF reports show "Last commit (branch)".
The `unmaintained` risk factor, the `unmaintained_1yr` / `unmaintained_2yr`
counts and the `no_unmaintained_months` policy rule use the same combined
value, so the report, the score and the policy agree.

GitHub's `pushed_at` is **not** used for the Maintenance axis. It moves on a
push to any branch, Dependabot branches included, so a repository whose default
branch stopped moving years ago can look active. It is reported as
`maintainer.last_commit_date`, and in the text report's maintainer section as
"Last push (any branch)". It still sets `maintainer.activity_pattern`, which
drives the `maintainer_inactive` risk factor and the `takeover_candidate` flag,
so those two can disagree with the Maintenance axis until they move to the
default-branch date.

**Deprecation.** A module is deprecated when the `go.mod` of its latest version
carries a `// Deprecated:` notice on its `module` directive (the rule `go list
-m -u` and `go get` apply, parsed with `golang.org/x/mod/modfile`), or when the
module proxy answers `@v/list` with 410. The notice usually names the
successor and is reported as `maintenance.deprecation_message`, in the text and
PDF reports and in the `no_deprecated` policy violation. Deprecated, like
archived, sets the Maintenance component to 100 whatever the dates: the
maintainers have said to move off the module, and a recent commit (for example
on `github.com/golang/protobuf`) does not change that. Deprecation does not set
the `archived_floor` headline candidate.

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

Neither `integrity_floor` nor `forbid_replace_redirect` looks at `in_build`.
A `replace` directive is a `go.mod`-level statement about how the module graph
is resolved, and it applies whether or not any package of the replaced module
is currently imported; a redirect that is dormant today becomes live the
moment an import is added.

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
| Confirmed test-only (`IsTestOnly == &true`)     | INFO     | None — surfaced for transparency  |
| Confirmed outside the build (`InBuild == &false`) | INFO   | None — surfaced for transparency  |
| Direct dependency, otherwise                    | MEDIUM   | +4 per-dependency penalty         |
| Transitive dependency, otherwise                | LOW      | +2 per-dependency penalty         |

An unknown classification (`IsTestOnly == nil` or `InBuild == nil`) is treated
as neither test-only nor outside the build, consistent with the scorer's
general convention of under-discounting rather than silently applying a
discount on unverified data.

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
preset) to fail CI on any pseudo-version pin that is not test-only and not
outside the build. Unlike `forbid_replace_redirect`, this rule **does** exempt
confirmed test-only dependencies and confirmed outside-the-build dependencies
— a pseudo-version pin is a provenance/pinning-hygiene signal about code on
the import path, not a hijack vector, so test-time exposure to CI secrets is
not the relevant threat model here.

## Build membership

A module can be in the dependency graph without being part of what you ship:
`go.mod` requires it (often through a dependency's own `go.mod`), but no package
of it is imported by your code. Scoring such a module as if it were compiled in
makes it drive the headline for a risk it cannot cause. After the graph is
resolved, `unisupply` therefore classifies every module against the main
module's own package graph and records three facts per dependency in the JSON
report.

### How it is classified

For each of `linux`, `darwin` and `windows` on `amd64` and `arm64`, with
`CGO_ENABLED=0` and `CGO_ENABLED=1`, it runs two lists in the main module's
directory:

1. **Production:** `go list -e -deps ./...`, the modules whose packages the main
   module's non-test code imports, directly or transitively.
2. **Production plus tests:** `go list -e -deps -test ./...`, which adds only
   the packages the main module's own tests import.

That is 24 `go list` runs (four at a time); a module counts as present when any
target lists it. Every GOOS/GOARCH pair is listed whatever the host, so the
verdict for a module imported only from an `_amd64.go` or `_arm64.go` file does
not depend on the machine the scan runs on. In offline mode the lists read only the local module cache and
classification is unavailable on a cold cache. They also run with
`-mod=readonly`, so a scan never rewrites the scanned project's `go.mod` or
`go.sum`; if either needs updating (`go mod tidy`), classification is
unavailable and the warning says so instead of blaming the cache.

`go list all` is deliberately **not** used. For a `go.mod` that declares go 1.16
or newer, `all` and `all -test` contain the same modules, so comparing them can
never report a test-only module. Below go 1.16, `all` additionally contains the
packages needed by the *dependencies'* own tests, so a module such as
`gopkg.in/check.v1`, used only by a dependency's tests, would be classified as
production (this is what put it at the top of the `spf13/cobra` headline). The
`-deps ./...` lists do not have either problem, whatever `go` version `go.mod`
declares.

`-e` keeps a per-package error from failing the whole listing. A package error
whose module is known (for example a `//go:embed` pattern that matches nothing
because the build output is gitignored and absent from a fresh clone) is
tolerated and named in a scan note, not a warning: classification is
unaffected, so the text report lists it under "SCAN NOTES" rather than "SCAN
LIMITATIONS", and the JSON report carries it in `notes`. A package that no module provides, a
missing `go.sum` entry or a failed lookup is not tolerated: with `-e` the
package would be listed without a module and its module would silently look
absent, so that platform is treated as failed instead.

### What it records

| JSON field | Value | Meaning |
|------------|-------|---------|
| `test_only` | `true` | Imported only by the main module's tests: in the test list on at least one platform, in no production list |
| | `false` | In a production list on at least one platform |
| | absent | Unknown |
| `in_build` | `true` | In a production or test list: some package of the module is compiled into the main module or its tests |
| | `false` | In the module graph only: no list contains it |
| | absent | Unknown |
| `platforms` | `["windows"]` | A production module listed on a strict subset of the three GOOS values (on either architecture), for example a module imported only from a `_windows.go` file |
| | absent | Built on all three, or unknown; not an assertion about other GOOS values. An architecture-only import is not reported here |

`in_build` is three-state and a consumer must never read absence as `false`:
only an explicit `false` is a confirmed graph-only module. Every consumer
below applies a discount only for a confirmed `false` (or a confirmed
`test_only: true`); an unknown value never discounts. The text and PDF reports
show an `outside build` label next to `test-only` under the same rule.

### Limits and guards

- **Build tags.** A package behind a custom tag (`//go:build integration`) is in
  no list, so a module imported only there looks graph-only. Guard: a module
  that `go.mod` requires **directly** (no `// indirect`) but that no list
  contains gets `in_build` absent, not `false`, and so does every module
  reachable from it in the module graph (`go mod graph`), since the tagged
  build compiles that requirement's own dependencies. The rule is "reachable
  from", not "reachable only through": for go 1.17 and newer, `go mod tidy`
  lists every module the tagged code needs as a `// indirect` requirement of
  the main module, so those modules also have an edge from the main module. A
  real case is gin, which imports `github.com/bytedance/sonic` only under
  `-tags=sonic`: sonic and the modules it pulls in (`cloudwego/base64x`,
  `klauspost/cpuid/v2`, `twitchyliquid64/golang-asm`, `golang.org/x/arch`,
  ...) are all left unknown. The module graph is coarser than the package
  graph, so modules that sonic's own tests need, and nothing compiles, are
  left unknown too. Other indirect modules are not guarded: the main module
  cannot import them directly, so graph-only is the likely reason they were
  not found.
- **`tool` directives.** A module needed only by a go 1.24 `tool` directive is
  in no list: `go tool` builds the tool separately, and nothing of it is linked
  into the main module. It is reported as `in_build: false` like any other
  graph-only module, so the outside-the-build exemptions below apply to it.
- **`tools.go` files.** The older way to pin a tool is a file behind
  `//go:build tools` that blank-imports the tool's package. That import makes
  the tool a direct requirement in `go.mod`, but the `tools` tag is never set,
  so no list contains it. The build-tag guard above therefore applies: the tool
  and every module reachable from it in the module graph are left unknown and
  counted as built. For a large tool such as a linter, that is its whole
  dependency tree, and those modules can then raise the headline. This errs
  toward counting too much, never too little. Declaring the same tool with a go
  1.24 `tool` directive instead gets `in_build: false` for its modules. A
  package-level refinement that would narrow this is tracked in
  [#139](https://github.com/unidoc/unisupply/issues/139).
- **Platforms.** Only `linux`, `darwin` and `windows` on `amd64` and `arm64`
  are listed. A module imported only on another GOOS (`freebsd`, `js`, ...) or
  another architecture (`386`, `riscv64`, ...) is not seen.
- **Per-platform failure.** A GOOS/GOARCH target whose lists fail (for example a package that
  does not build on Windows) does not discard the others. Everything the failed
  runs did resolve still counts as evidence that a module is built; the
  platforms that succeeded classify the rest. A failed platform cannot prove
  that a module is absent, so while any platform has failed, a module found on
  no list gets `in_build` absent rather than `false`, a `test_only: true`
  verdict is withheld (the module may be production on the failed platform) and
  `platforms` is left unset. The warning names the failing GOOS and GOARCH. Only when
  every platform fails is classification unavailable: every field stays absent
  and a warning says so.

### What honours it

| Consumer | Test-only | Outside the build | Notes |
|----------|-----------|-------------------|-------|
| `p95_dep_risk` population | excluded | excluded | See [Headline candidates](#headline-candidates) |
| `archived_floor` | skipped | skipped | An archived module that is never compiled in cannot be an unpatchable risk to the build |
| Time bombs (archived, KEV, CRITICAL CVE) | skipped | skipped | Nothing that is not compiled in can detonate in the shipped code |
| Pseudo-version pin severity and penalty | INFO, no penalty | INFO, no penalty | See [Pseudo-version pins](#pseudo-version-pins) |
| `forbid_pseudo_versions` policy rule | exempt | exempt | Same reason |
| `no_unmaintained_months`, `no_archived`, `no_deprecated` policy rules | not exempt | exempt | The scorer's archived floor and time bombs already skip modules that are not compiled in; the gate now agrees. An unknown `InBuild` is still checked |
| CVE severity downgrade (`severity_adjusted`) | −1 tier | not applied | Reachability already downgrades a CVE in a module that is not linked in (`required` tier); a second discount would count the same fact twice |
| `cve_floor` | skipped | not applied | Same reason |
| `integrity_floor`, `forbid_replace_redirect` | `integrity_floor` skips; policy rule does not | not applied | A `replace` directive is a `go.mod`-level signal; see [Integrity](#integrity) |

Because test-only classification now works, every test-only discount above
applies to real scans for the first time, so scores and policy results can
change for repositories with test-only dependencies.

## Risk bands

| Level    | Score   |
| -------- | ------- |
| LOW      | 0–25    |
| MEDIUM   | 26–50   |
| HIGH     | 51–75   |
| CRITICAL | 76–100  |

## Overall project score

The project-level score in the report header is the highest of five
candidates; see `pkg/scorer/risk.go` for the exact aggregation. A tie between
candidates is resolved in this order: `severity_adjusted`, `p95_dep_risk`,
`archived_floor`, `cve_floor`, `integrity_floor`.

### Headline candidates

| Candidate | What it measures |
|-----------|------------------|
| `severity_adjusted` | Step function over the reachability- and test-only-downgraded CVE counts |
| `p95_dep_risk` | 95th percentile (nearest rank) of per-dependency risk scores over the modules that are built |
| `archived_floor` | 51 (HIGH) for an archived built module, 60 for a direct one |
| `cve_floor` | Floor from the post-reachability tier of the worst CVE |
| `integrity_floor` | 51 or 60 for a redirect `replace`; CRITICAL on a `go.sum` mismatch |

**`p95_dep_risk` population.** Confirmed test-only modules and confirmed
outside-the-build modules (`in_build: false`) are not in the population. A
module whose classification is unknown (`nil`) is counted: unavailable
classification means "assume built", which under-discounts rather than hiding a
module. If every dependency is filtered out the candidate is 0, as for an empty
graph. The non-normative `mean_dep_risk_score` and
`diagnostics.max_dep_risk_score` still cover the whole graph, while
`diagnostics.p95_dep_risk_score` mirrors this candidate.

**Deterministic driver, `tied_with`.** Scores tie often (a 4-way tie at the p95
index is common), and which tied module is named used to depend on map order.
Modules are now ordered by score and then by module path, so the same inputs
always name the same module. When other built modules share the p95 score the
headline candidate carries `tied_with` (the number of *other* modules at that
score) and its reason reads "one of N modules at S"; the `driving_item` is then
one of N equally scored modules, not the sole cause.

**Archived floor.** Only built modules can set it, with the same
unknown-counts rule as the p95 population.

**Health-only headline.** When the vulnerability scan ran and
`severity_adjusted`, `cve_floor` and `integrity_floor` are all 0, the grade is
decided by dependency health alone. The headline reason then starts with "no
reachable vulnerabilities; grade reflects dependency health (maintenance,
maturity) of built modules", so a reader does not take the driving module for a
vulnerability finding. This is an explanation only; the score and level are
unchanged. When no dependency has an `in_build` verdict the reason says "of all
modules in the dependency graph (build classification unavailable)" instead.
The separate case where the vulnerability scan did not run is the
[unscored headline](#unscored-headline).
