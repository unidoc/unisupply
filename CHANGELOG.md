# Changelog

All notable changes to `unisupply` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-10-23

Library-caller release. A failed scan now comes back as a typed
`*scanner.ScanError` with a `Kind` (transient, permanent, too large) and a
stable reason code, so a service that embeds `runner.Run` can decide whether to
retry; the JSON carries the same `code` and `kind` under `grade.pending`. A
panic in a scanner worker is returned as an error instead of ending the
process, and `Options.Timeout` is documented and tested as a per-request limit.
`scanner.ScanVulns` now returns an error when govulncheck fails (see
Improvements). The grading rules are unchanged from v0.7.0.

Known issue: the v0.8.0 release binaries are built with Go 1.26.9, which has
GO-2026-6809 (`crypto/x509` does not distrust compromised intermediate
certificates; fixed in Go 1.26.10). govulncheck reports it as reachable from
unisupply. To get the fix, install with Go 1.26.10 or newer
(`go install github.com/unidoc/unisupply/cmd/unisupply@v0.8.0`).

### New Features

#### Typed scan failures with stable reason codes

- **A failed scan now comes back as a `*scanner.ScanError`** (use `errors.As`) with a `Kind` that says whether a retry
  can help (`FailTransient`: network, timeout, rate limit; `FailPermanent`: the project cannot be scanned as it is;
  `FailTooLarge`: a limit was exceeded), a stable `Reason` code, and `Err`, the tail of govulncheck's or the go
  command's own output (the last 40 lines or 4 KiB). `Error()` is `reason: cause`, `Summary()` is the same on one line,
  and `Kind.String()` gives `transient`, `permanent` or `too_large`. The zero `Kind` is `FailPermanent`, so a
  `ScanError` built without one is never retried.
- **The reason codes are exported constants** and are a contract: `needs_newer_go`, `no_go_mod`, `multiple_mains`
  (`func main` declared twice), `mixed_packages` (two package names in one directory), `no_packages`, `cgo_only`,
  `build_constraints` (an imported package, a dependency or one of the project's own, has no Go file for this build: cgo
  off, another GOOS, a build tag), `cgo_dependency`, `missing_gosum`, `module_fetch`, `rate_limited`,
  `vulndb_unreachable`, `scan_deadline`, `internal_panic` and `unknown`.
  An unknown failure is `FailPermanent`. `cgo_only` is reported when cgo is off for the scan and a file of the module
  imports `"C"`; without that, "no packages matched" is `no_packages`. `cgo_dependency` is reported when cgo is off for
  the scan and the excluded package's own files import `"C"`; without that, the failure is `build_constraints`.
- **A scan stopped by its context's deadline is `scan_deadline`** (`FailTooLarge`), and `errors.Is(err,
  context.DeadlineExceeded)` holds for it. A permanent cause in the output still wins over the deadline, and a scan whose
  context was canceled is `unknown`. Once the context has ended, network text in the output is not read as
  `module_fetch` or `rate_limited`: the timeout is the scan's own.
- **`module_fetch` covers the network faults of a download**: a refused or timed-out connection (`dial tcp`, `i/o
  timeout`, `connection timed out`), a cut download (`unexpected EOF`), an HTTP/2 stream reset (`stream error: stream
  ID 3; INTERNAL_ERROR`) and a 5xx from the proxy. Network wording that no rule knows is `unknown`, which is
  `FailPermanent`: a caller that retries should give `unknown` a small, bounded number of retries rather than none.
- **`rate_limited` matches the wording of a refused request** (`rate limit exceeded`, `secondary rate limit`, `429 Too
  Many Requests`), not a package path such as `go.uber.org/ratelimit` in a build error.
- **Where it appears:** `Result.VulnScanErr` (still typed `error`) when the vulnerability scan fails, the error of
  `scanner.ScanVulnsWithOptions`, and the early failures of `runner.Run` (no go.mod, an unreadable go.mod, dependency
  resolution). `scanner.CheckToolchain` is unchanged, and the CLI's error line prints only the cause, as before. Report
  warnings change in two ways: a refused toolchain's line now carries the code
  (`Vulnerability scan failed: needs_newer_go: this unisupply was built with ...`), and a package-loading failure names
  the project's files relative to the project (`b.go:3:6: ...`), not by their path on the scanning machine.
- **`grade.pending` in the JSON has `code` and `kind`** when the vulnerability scan failed with a typed scan failure:
  the reason code (`"code": "multiple_mains"`) and the kind (`"kind": "permanent"`, or `transient`, `too_large`). They are
  set only for the `vulnerability_scan` check and are absent for any other, and for a scan that failed with an error that
  is not a `ScanError`. A caller that decides on a retry reads `kind`; `reason` keeps its text, with the code in front, and
  is for people.

### Improvements

#### The published reason for a failed scan names the cause

- `grade.pending.reason` and the text and PDF reports used to end at `govulncheck: loading packages:` when the packages
  could not be loaded, because only the first line of the error was kept and the cause is on the following lines. They
  now give the reason code and the line that decided it, for example
  `multiple_mains: b.go:3:6: main redeclared in this block`, even when an unrelated error is listed before it. The line
  starts at the cause, without govulncheck's `loading packages: err: exit status 1: stderr:` wrapper
  (`needs_newer_go: go.mod requires go >= 1.27.0 (running go 1.26.9; GOTOOLCHAIN=local)`), and is held to 4 KiB. The
  project's directory and the module cache are cut from the text (as the go command reports them, symlinks resolved), so
  the reason does not carry a path of the scanning machine: a dependency reads `github.com/x/y@v1.2.3/...`. GOROOT paths
  are kept.

#### Behaviour change: `ScanVulns` returns an error when govulncheck fails

- `scanner.ScanVulns` and `scanner.ScanVulnsWithOptions` used to return a nil error when govulncheck failed: the failure
  was only in `warnings`, with `scanned` false and any partial vulnerabilities it had parsed. They now return a
  `*scanner.ScanError` as well, next to the same `vulns`, `warnings` and `scanned`. A caller that stops at
  `if err != nil { return }` now drops the partial results and warnings it used to get: keep reading them, or branch
  with `errors.As`. `runner.Run` handles this. The early errors of `runner.Run` were errors before; their `Error()` now
  starts with the reason code (`no_go_mod: no go.mod found in ...`).

#### `Options.Timeout` is a per-request limit

- `runner.Options.Timeout` bounds each outbound HTTP request of the scanners, never the scan. Give the scan its limit
  as the deadline of the context passed to `Run`; passing it as `Timeout` lets one stalled request use all of it. The
  documentation now says so, and tests pin it: the timeout fires without a context deadline, and a shorter context
  deadline wins. govulncheck's fetch of the vulnerability database and the go command's module downloads are bounded
  only by the context.

#### Dependencies

- Upgraded `golang.org/x/vuln` `v1.8.0` → `v1.9.0` (direct dependency). govulncheck runs in-process, so
  `scan.govulncheck_version` now reads `v1.9.0`.
- Upgraded `golang.org/x/mod` `v0.41.0` → `v0.42.0` and `golang.org/x/term` `v0.46.0` → `v0.47.0` (direct), and
  `x/crypto`, `x/net`, `x/sync`, `x/sys`, `x/telemetry`, `x/text`, `x/tools` to current releases. None of these
  upgrades clears an advisory: govulncheck reports the same findings for v0.7.0 and v0.8.0.

### Bug Fixes

- **A panic in one of the scanners no longer ends the calling process.** A panic in a worker goroutine of the dependency
  resolver or of the maintenance, maintainer, activity, resilience, fix-date and response-history scans was not
  recoverable by the caller, and ended a service that embeds `runner.Run`. The worker's panic is now carried back to
  `Run`, which returns a nil `Result` and a `*scanner.ScanError` with reason `internal_panic` (permanent) whose `Err`
  is the panic value and the stack of the goroutine it happened in. Panics inside govulncheck's own goroutines, fatal
  runtime errors such as concurrent map writes, and the process being killed are not covered.

## [0.7.0] - 2026-10-16

Grading release. The published result is now one letter, A to F, with the row
that decides it and the evidence behind it, in place of the 0-100 risk score.
This is a breaking change to the JSON, text, PDF and SBOM output and to the
policy file (see "Breaking: Grading v2" under Improvements). The scan pipeline
is now an importable package, `pkg/runner`. The grade's inputs are more
precise: how each reachable vulnerability is reached, severity from OSV alias
records, which modules are in the build, maintenance from the default branch's
last commit, go.mod deprecation notices, and standard-library vulnerabilities.

### New Features

#### Inputs of the grade

- **The module's own advisories** (`scanner.ScanModuleAdvisories`): OSV advisories for the exact published version of
  the scanned module, assumed called (govulncheck does not check the module it starts from).
- **Fix-release dates** (`scanner.ResolveFixDates`, `ResolveStdlibFixDates`): the later of the advisory's fix date and the
  module proxy's time for the first fixed version.
- **Retraction** is read from the `retract` directives in the latest go.mod and graded like deprecation.
- **Archived status** now follows the repository a module is published from (vanity paths such as `gopkg.in/yaml.v3`),
  and an archived flag that could not be read is reported as unchecked, never as not archived. A repository that does
  not exist (404) is reported as `repo_not_found` and is not blamed on the GitHub API.
- **Build status:** a module that is not listed in `go.mod` and is reachable only from a build-tag-only requirement is
  now classified as not built instead of unknown (Go 1.17 and newer `go.mod` files).
- **Strongest call path:** a path that does not just format a message (`fmt`, `log`, an `Error` or `String` method) is
  preferred, and `condition` says what the project must do to reach the vulnerable code.
- **Response history** (`scanner.ScanResponseHistory`, `--response-history`): the median number of days the project took
  to adopt comparable fixes, with at least three samples.
- **Request bounds:** the resilience scan samples at most 24 versions per module and a shared budget of 3,000 date
  requests, and GitHub repository, owner and latest-commit answers are cached per scan.



- **Audit fixes after review (same release):**
  - `--module-version` must be a full version (`v1.4.0`, `v1.4.0-rc.1`, `v2.0.0+incompatible`), checked before any scan;
    `--response-history` needs `--module-version`. A policy is now evaluated even for a module with no dependencies (it
    used to be skipped with the report), and `--help` says the exit code ignores the grade unless a policy is given.
  - The grade notes what it could not check instead of reading it as clean: a reached finding whose known-exploited status
    could not be checked (CISA catalog), and modules whose archived flag was never read for a reason other than a failed
    call. A row whose upkeep could not be read has no letter. A checksum mismatch is always reported
    (`checksum_mismatch`), also when another row already scores F.
  - A module confirmed not to be compiled in is graph-only whatever its reachability says; `C*` marks only a C that
    rests on an estimate; a row's vulnerability score is capped at 100; the +5 further-advisory step is for reached findings
    only; Pending is decided on the letter a missing check could change, not on the score.
  - Request bounds: the fix-date stage shares one 60-second deadline, response history is bounded (fixes per dependency,
    a request budget and a deadline), and the resilience budget is allocated in module order so a scan is repeatable.
  - A Pending grade publishes no score and no deciding row (what is known is in `pending.known`); the same vulnerability under
    two identifiers merges the same way whatever the order; the archived flag of `gopkg.in/*` modules is read through the
    host's repository convention (the module proxy records no origin for most of them); `-f` and `--policy-preset` are
    checked before the scan; the token is validated when `--module-version` is set even for a module with no dependencies;
    `policy.Evaluate` no longer panics when only a grade is passed.
  - The retired score wording is gone from the published warnings; `.github` workflows and scripts read the grade.

#### How long the fix existed before the scanned version was released

- With `--module-version`, the module proxy's release time of that version (`scanner.ModuleVersionTime`, cached) is
  compared with each fix's release date. The JSON `response.fix_age_at_release_days` and the text "Fix available for 87
  days before this version was released (120 days to the scan date)" say how long the fix had existed at release; both are
  absent when the release time is unknown or the fix came after the release. The letter does not change.

#### NVD API key for severity lookups

- **`--nvd-api-key` (or `NVD_API_KEY`) raises the NVD rate limit** of the CVE
  severity fallback from 5 to 50 requests per 30 seconds. The key is sent only
  as an `apiKey` header to `services.nvd.nist.gov`, with surrounding whitespace
  trimmed. A key NVD rejects (404 with `message: Invalid apiKey.`, or 401)
  produces one warning and the scan continues unauthenticated, so a bad key
  never costs severities that no key would have found. A 403 does not drop
  the key. `pkg/runner.Options`
  gains `NVDAPIKey`, and `scanner.ScanVulnsWithOptions` is the new entry point
  (`ScanVulns` is unchanged).

#### Call path for every reachable vulnerability

- **JSON reports now carry `call_path` on each vulnerability whose
  reachability is `called`:** one example of how the project reaches the
  vulnerable function, outermost frame first, condensed to the entry frame, the
  frame where each package hands over, and the vulnerable function itself
  (at most 8 entries). A longer path is cut in the middle and a `"..."` entry
  marks the cut, so a consumer must not treat every entry as a function name.
  When a vulnerability has several vulnerable symbols the shortest path is
  kept, with ties broken on the path string, so the choice does not depend on
  govulncheck's output order. It is static-analysis evidence of reachability,
  not proof of exploitability. Vulnerabilities that are only `imported` or
  `required` have no call path. `pkg/runner.Result` carries the same field
  through `scanner.Vulnerability.CallPath`.
- **`call_trace` gives each `call_path` entry a source position (#134).** It is
  an array of `{name, module, version, file, line, column, project, elided}`
  objects (empty fields omitted), the same length and order as `call_path`,
  present only for `called` findings; the cut slot is `{"elided": true}`. A
  non-sink frame's position is the call it makes and the last entry's is the
  vulnerable function's declaration; because the path is condensed, a kept
  frame's position can point at a call to a dropped frame. `file` is relative
  to that frame's own module (the standard library's to GOROOT), so read it
  with `module` and `version`; it is dropped when govulncheck reports an
  absolute path or one outside the module, while `line` and `column` are kept.
  `project` is true for frames in govulncheck's scan roots, taken from its
  `SBOM` message, and is false everywhere with a govulncheck that emits none.
  Equally short paths are ordered on the path string and then on frame
  positions. Exposed as `scanner.Vulnerability.CallTrace` and
  `scanner.CallFrame`.
- **`called_symbols` lists every vulnerable symbol found called for an
  advisory in a module (#134).** govulncheck emits one finding per symbol while
  `call_path` keeps one path. The list is sorted, deduplicated and capped at 20
  (the first 20 in sorted order). Exposed as
  `scanner.Vulnerability.CalledSymbols`.
- **Text and PDF reports show a `Reached via:` line under each called
  finding.** For example `Reached via: example.com/u1repro.main (main.go:13) →
  golang.org/x/crypto/ssh/agent.keyring.Add`. `(file:line)` is shown only on
  project frames, `...` marks a cut, and a `Vulnerable symbols called:` line
  follows when there is more than one symbol. The PDF separates frames with
  ` > ` because its standard font has no arrow glyph. There is no call-site
  count: govulncheck emits one representative stack per symbol, so the number
  of call sites is not in its output. `call_trace` and `called_symbols` do not
  affect scores or policy results.

#### `pkg/runner`: the scan pipeline as an importable package

- **`runner.Run(ctx, Options)` runs the full scan-and-score pipeline in
  process.** `cmd/unisupply` now calls it, so the CLI and library callers share
  one implementation; flags and output are unchanged. Offline mode is the
  process-wide `pkg/offline` switch, so call `offline.Enable()` before `Run`.
- **`Result` tells a library caller when a scan is incomplete.**
  `VulnScanErr` is non-nil when the vulnerability scan did not complete, and
  `Interrupted` is true when the context ended before every scanner finished.
  A caller must not present either as "no vulnerabilities".
- **`Options.RequireGithubToken` and `Result.GithubTokenRejected`.** `Run`
  validates `Options.GithubToken` with GitHub before the scanners use it. With
  `RequireGithubToken`, a missing, rejected or unvalidated token fails `Run`
  with an error wrapping `runner.ErrGithubTokenPrecondition`; without it, a
  rejected token is dropped, the scan runs unauthenticated, and
  `GithubTokenRejected` is set.

### Improvements

#### Breaking: Grading v2, one letter A to F instead of a 0-100 score

The published result is now a letter with the evidence behind it, decided by one rule you can trace (see
[docs/grading.md](docs/grading.md)). **This changes the JSON, text, PDF and SBOM output and the policy file, and it
breaks consumers that read the old fields.**

- **New `grade` object in the JSON report, and in `pkg/runner.Result.Grade`.** The module itself and every dependency
  get one score (the higher of its vulnerability score and its upkeep score); the letter comes from the worst row, which
  the result names with a one-sentence reason. Called vulnerabilities score 90/70/45/15 (critical/high/medium/low),
  imported-only code at most 50, graph-only findings are shown and not graded, a called known-exploited finding is F,
  test-only findings are halved, archived or deprecated modules count up to C only, and whole-tree rules raise the letter
  (three called high or critical findings, any called critical, a checksum mismatch: F; five called or imported high or
  critical findings: at least D). A finding with no published severity is scored as medium and the letter is marked `C*`.
- **Pending.** When a check the grade needs did not run (vulnerability scan failed, scan did not finish, the module's
  own status or advisories could not be read, a dependency's maintenance data is missing and could change the letter) the
  grade has no letter and says which check and why. It is never an A.
- **Response window.** A fix released within the last 14 days is labelled with the date its window ends; the label never
  changes the letter. `fix_released_at` and `fix_date_source` come from the module proxy.
- **Deprecated, kept for one release (JSON only), derived from the grade:** `overall_risk_score` (the worst row's policy
  value), `overall_risk_level` (the coarse band of the letter: A and B read LOW, C MEDIUM, D HIGH, F CRITICAL, UNKNOWN
  without a letter), `headline` (the deciding row in the old shape, with an empty `candidates`), the `*_risk_count`
  summary fields (dependency rows by level) and the per-dependency `risk_score` / `risk_level`. They no longer carry their
  old meaning (a weighted risk score); `deprecated_fields` in the report lists them. On a Pending result
  `overall_risk_score`, `headline.score` and the per-dependency `risk_score` are omitted (not 0, which a v1 gate would
  read as the cleanest result); `overall_risk_level` stays `UNKNOWN`. Read `grade` instead: they are removed in the next
  release.
- **Removed from every output (no equivalent in the grade):** `headline_driver`, `mean_dep_risk_score`,
  `severity_adjusted_vuln_score`, `worst_cve_*`, `diagnostics`, `debug_scoring`, `headline_unscored_reason`, the
  per-dependency `score_breakdown` and `risk_factors`, `severity_scored`, `takeover_candidates` (and
  `pkg/runner.Result.Takeovers`), the AI-generation and EPSS-adjusted displays, and the SBOM `unisupply:risk_score` /
  `unisupply:risk_level` (now `unisupply:grade` and `unisupply:grade_reason`). The Go types behind them in `pkg/report`
  (`JSONTakeover`, `JSONScoreBreakdown`, `JSONDiagnostics`, `JSONCandidate`) are removed; `JSONHeadline` and the
  deprecated fields above remain.
- **CLI:** `--min-risk` and `--debug-scoring` are removed. New `--module-version` grades the scanned module itself at a
  published version, and `--response-history` adds how fast the project adopted past fixes.
- **Policy:** `max_risk_score` and `max_overall_score` are removed (a policy file that contains them is rejected). New
  `max_grade` ("A" to "F") and `allow_pending`. A Pending grade fails `max_grade` unless `allow_pending` is set. The
  presets are `strict` = B and `moderate` = C. `pkg/policy.EvalInput` gains `Grade`.
- **Standard library findings** are graded as a row named `stdlib`.
- **Go API breaks** (library callers of `pkg/report`, `pkg/policy`, `pkg/runner`, `pkg/grade`):
  - `report.TextOptions`, `report.JSONOptions` and `report.PDFOptions` no longer have a `Takeovers` field.
    `report.TextOptions.MinRisk` is removed too (no flag set it), and the text writer no longer prints the
    `debug_scoring` block.
  - `report.JSONReport` loses `OverallRisk`, `OverallLevel`, `MeanDepRiskScore`, `SeverityAdjustedVulnScore`,
    `HeadlineDriver`, the headline and diagnostics objects, `takeover_candidates` and the per-dependency risk fields.
    The types `report.Headline`, `JSONHeadline`, `JSONCandidate`, `JSONDiagnostics`, `JSONScoreBreakdown` and
    `JSONTakeover` are removed. `JSONDependency` loses `RiskScore`, `RiskLevel`, `RiskFactors` and `ScoreBreakdown`,
    `JSONSummary` loses the `*RiskCount` fields, and `JSONVuln` loses `SeverityScored`.
  - `report.SBOMOptions` gains `Grade`. CycloneDX and SPDX carry `unisupply:grade` per component with the same label as
    the text report (`C*` when estimated) and no property or annotation for a row with no letter, plus the overall grade
    (a letter, or `PENDING (<check>)`) on the root component (CycloneDX `metadata.component`) and as an SPDX document
    annotation.
  - `policy.Policy.MaxRiskScore` and `MaxOverallScore` are removed. `MaxGrade` and `AllowPending` are new. An enabled
    `max_grade` **fails** when `policy.EvalInput.Grade` is nil (grading did not run), and on a Pending grade unless
    `AllowPending` is set. `Result.FormatText` now prints warnings on a PASS (`PASS (1 warning): ...`) and counts only
    errors in the `FAIL: N policy violation(s)` line, listing warnings separately.
  - The AI-generation scanner no longer runs and its result is not published (`pkg/scanner/aigen.go` is kept but not
    called).
  - Fixes that need a newer Go: each finding with a fix now says which Go the fixed version needs (`fix_requires_go`, the `go`
    directive of its go.mod, read from the module proxy) and whether taking it raises the scanned module's minimum Go
    (`response.fix_compat` = `raises_minimum` | `compatible`, in the response text); `grade.notes` and `grade.fixes_need_newer_go`
    count them. The letter does not change for it. New `scanner.ResolveFixGoRequirements`, `Vulnerability.FixRequiresGo`.
  - Severity lookups (from the 214-module replay): a lookup that FAILED is now a check that did not run, not an
    unpublished severity. NVD requests are paced (5 per 30 s without `NVD_API_KEY`, 50 with), retried with backoff and
    `Retry-After` (up to 3 times, within a 3-minute budget), and every CVSS v3.1, v3.0 and v4.0 metric counts, also a
    Secondary (CNA) one with the record still "Awaiting Analysis". When it still fails, the grade is Pending
    (`pending.check` = `severity_lookup`) if a different severity would change the letter; before, the finding was
    estimated as MEDIUM and 23 modules hit by the 8 Oct x/net advisories graded `C*` instead of F. `grade.Finding` has the
    new field `SeverityLookupFailed`.
  - A dependency with no tagged release (the proxy answers 404 for `@latest`) is read at its pinned version, so it no
    longer leaves the grade Pending for ever (`itchyny/go-yaml`).
  - `runner.Options.StrictArchivedStatus` is new (`--strict-archived`, default off): by default a grade is given when the
    only gap is a dependency's archived flag that GitHub's rate limit kept unread (an archived dependency adds at most 20 to
    its row): the result lists the modules in `grade.archived_unread` and says in a note that the letter may be one band
    better. With the strict rule the grade is Pending instead (a service that publishes letters sets it). The module's
    own archived flag is always required.
  - `runner.Options.GradeStdlib` is new (`--grade-stdlib` on the CLI, default off): the Go standard library's advisories
    are always listed (`runner.Result.StdlibVulns`, with the Go release they were matched against in `grade.notes`), but
    they decide the letter only when it is set, as in the agreed rules. A module with no dependencies runs the
    vulnerability scan too and lists them (with the scan block); a failed scan is Pending only under `--grade-stdlib`,
    otherwise a warning. The "scanned at go1.x" note is written only when the scan ran (also on the multi-dependency
    path, where it said so after an offline or failed scan).
  - `archived_unread` and its note appear only when an unread archived flag could change the letter (an unread flag adds
    at most 20 to a row, so only an A can move); on C, D and F, or when the row already scores 20 or more, the list is
    empty and there is no note. A policy `max_grade` now fails when the letter equals the maximum and
    `archived_unread` is not empty (`max_grade: "A"`), and otherwise passes with a warning naming how many flags were
    unread and saying to set `GITHUB_TOKEN`.
  - The CISA KEV catalog fallback has an age cap of 30 days (`scanner.KEVMaxStaleAge`): a cached copy older than that is
    not a catalog, so known-exploited status is unchecked (Pending `known_exploited`, as with no catalog); within it,
    the note and warning state the copy's date and age.
  - `scan.govulncheck_version` is the version of `golang.org/x/vuln` linked into the binary (from the build info), not
    govulncheck's `scanner_version`, which in-process is unisupply's own version. It is omitted when the build info does
    not list it.
  - A locally replaced dependency is detected with go.mod's own rule (`GoMod.ReplacementFor`): a replace scoped to one
    version (`example.com/lib v1.0.0 => ../lib`) does not make another selected version local.
  - `grade.Result` gains `ChecksumMismatch` and `ChecksumDetail` (`checksum_mismatch`, `checksum_detail` in JSON), and
    a `grade.RowResult` may have an empty `Letter` (the key is present and `""`, not omitted): its upkeep could not be
    read (the text and PDF reports show `-`).
  - JSON contract since the first draft of this change: `upkeep_state` has the new value `not_assessed` (the module
    itself without a published version, a locally replaced dependency, the standard library); `pending.check` has the new
    values `checksum` and `known_exploited`; a Pending result has neither a letter, a `deciding` row nor a `score`.
- **Published scan warnings** no longer carry the retired score language: lines about excluded axis weights, scores
  that are "NOT comparable" and the high-EPSS "verify reachability manually" notice are dropped or shortened (for
  example "vulnerability scan did not run"). Warnings about data that could not be fetched are kept.
- **The 0-100 numbers kept in the grade rows** (`score`, `vulnerability_score`, `upkeep_score`, `grade.score`) are
  policy values shown for traceability, not a measurement and not a risk score. The CI/CD audit keeps its own 0-100
  score.
- **The repository's own CI** now reads `.grade.letter`, `.grade.pending`, `.grade.deciding` and `.grade.rows[]`; the
  weekly issue is filed on C, D, F or Pending. `.github/security-policy.json` sets `allow_pending`.

#### Scores can change in this release

- **Scores and policy results can change for existing projects, in both
  directions.** Scores can drop for repositories whose p95 or archived floor was
  set by a module that is only in the module graph and never built. Test-only
  classification now works for the first time, so every test-only discount (CVE
  tier, archived and CVE floors, time bombs, pseudo-version checks and the
  `forbid_pseudo_versions` exemption) applies to real scans; scores and policy
  results can change for repositories with test-only dependencies. Example from
  a real scan: `spf13/cobra` at `adbc881` went from 34 (driven by
  `gopkg.in/check.v1`, which is never built) to 26 (#135).

#### Build membership: `in_build` and `platforms`

- **JSON dependencies now carry `in_build` and `platforms`.** `in_build: false`
  marks a module that is in the module graph only: no package of it is imported
  by your code or your tests. `platforms` lists the operating systems
  (`linux`, `darwin`, `windows`) of a module built on only some of them, such as
  `github.com/inconshreveable/mousetrap` in `spf13/cobra`, which is imported
  only on Windows. Both are omitted when unknown, and an unknown value never
  discounts anything. The text and PDF reports label confirmed graph-only
  modules `outside build`, next to `test-only`.
- **Classification uses the main module's own package lists** (`go list -e
  -deps ./...` and `-deps -test ./...`, for each of linux, darwin and windows
  on amd64 and arm64, with `CGO_ENABLED` 0 and 1) instead of `go list all`.
  Every target is listed whatever the host, so the result does not depend on
  the machine the scan runs on. A package behind a custom build tag is not
  seen, so a module that `go.mod` requires directly but that no list contains
  is left unclassified rather than called graph-only, and so is every module
  reachable from it in the module graph (gin's `sonic` dependencies under
  `-tags=sonic`, for example). If one platform fails to list, the others still
  classify, and the warning names the one that failed. A module needed only by
  a go 1.24 `tool` directive is classified as outside the build. Under `--offline` these lists run with `-mod=readonly`,
  so the scanned project's `go.mod` and `go.sum` are never rewritten; when they
  need updating, classification is unavailable and the warning names that cause.
  See [docs/scanners.md](docs/scanners.md#build-membership).

#### The headline counts only modules in the build

- **`p95_dep_risk` and `archived_floor` ignore modules that are confirmed
  test-only or outside the build.** A module with an unknown classification is
  still counted. Previously an unmaintained module that was only in the graph
  could set the headline, or a HIGH archived floor, for code that is never
  compiled in.
- **The p95 driver is now deterministic and says when it is one of several.**
  Modules at the same score are ordered by module path, so repeated scans name
  the same module. When others share the score, the headline candidate carries
  `tied_with` (the number of other modules at that score) and its reason reads
  "one of N modules at S".
- **The headline says when dependency health alone decided it.** When the
  vulnerability scan ran and no vulnerability or integrity candidate scored,
  the reason now reads "no reachable vulnerabilities; grade reflects dependency
  health (maintenance, maturity) of built modules" before the driving module,
  so it is not mistaken for a vulnerability finding. Score and level are
  unchanged.

#### Modules outside the build are exempt from time bombs, pseudo-version checks and policy

- **Time bombs skip modules that are outside the build.** An archived or
  CRITICAL-CVE module that no package imports cannot detonate in the shipped
  code, so it is no longer listed.
- **A pseudo-version pin on a module outside the build is INFO with no score
  penalty**, as for a test-only module, and the `forbid_pseudo_versions` policy
  rule no longer fails on it.
- **The `no_unmaintained_months`, `no_archived` and `no_deprecated` policy rules
  skip modules that are outside the build.** `--policy-preset strict` no longer
  fails on an archived or unmaintained module that is only in the module graph,
  which the scorer already did not count. A module with an unknown classification
  is still checked, and so is a test-only module.
- **Some checks deliberately still apply to such modules:** CVE severity and
  `cve_floor` (reachability already discounts a vulnerability in a module that
  is not linked in), and `integrity_floor` and `forbid_replace_redirect` (a
  `replace` directive is a `go.mod`-level signal).

#### Maintenance uses the default branch's last commit

- **Scores can change in both directions.** A repository whose default branch
  is worked on but that rarely tags a release is no longer scored as abandoned,
  and a deprecated module is no longer scored by its dates at all (see below).
- **The maintenance score, the `unmaintained` risk factor, the unmaintained
  counts and the `no_unmaintained_months` policy rule use the newer of the last
  release and the last commit on the default branch.** The commit time comes
  from the module proxy (`@v/<branch>.info`, with the GitHub default branch,
  else `main`, then `master`), so it needs no token or GitHub quota and covers
  modules outside GitHub. With a token, the GitHub commits API is the fallback
  when the proxy query fails. GitHub's `pushed_at` is not used: it moves on
  pushes to any branch, Dependabot's included. The JSON `maintenance` object
  gains `last_activity`, `months_since_activity`, `activity_source` and
  `activity_branch`, and the text and PDF reports show "Last commit". The text
  report's maintainer section now labels its `pushed_at` date "Last push (any
  branch)". Without activity data the release age alone is used, as before.
  Branch queries time out after 10 seconds, and resolved branches and the
  `go.mod` files read for deprecation are cached on disk for 24 hours.
- **`no_unmaintained_months` is more lenient for repositories with recent
  default-branch commits:** a dependency passes when it was released or
  committed to within the limit, and the violation names both ages.

#### go.mod deprecation notices are read (#138)

- **A module is now deprecated when the `go.mod` of its latest version carries
  a `// Deprecated:` notice,** the way `go list -m -u` and `go get` report it.
  Before, only a 410 from the proxy counted, which almost never happens, so
  modules such as `github.com/golang/protobuf` were not reported. The message,
  which usually names the successor, is reported as
  `maintenance.deprecation_message`, in the text and PDF reports and in the
  `no_deprecated` violation.
- **A deprecated module's maintenance component is 100, like an archived
  one,** whatever its release or commit dates. `no_deprecated` is not enabled
  by either preset, so a custom policy that enables it can now fail on modules
  it previously passed.

#### Severity resolved from OSV alias records

- **Advisories whose severity was left `UNKNOWN` by NVD or GitHub rate
  limiting now resolve from OSV itself.** The GHSA and CVE aliases of an
  advisory are looked up on OSV before NVD and GitHub, which become fallbacks.
  CVSS v3.0/v3.1 vectors on CVE records are scored locally. The advisory's
  `severity_alias` JSON field names the alias that supplied the severity.
  On a cold, unauthenticated scan of a module with 35 reported advisories,
  NVD requests fell from 84 (68 rate-limited) to 24 (11 rate-limited), and the
  advisories with a published severity that were left `UNKNOWN` now resolve.
- **`severity_source: "unscored"` separates "not published yet" from "lookup
  failed".** When every source consulted (OSV, NVD, GitHub) answered but
  none has a severity, the advisory is reported as unscored instead of as an
  enrichment failure. A rate-limited or failed lookup still counts as a
  failure, because it may have missed a published severity. Scoring
  is unchanged (MEDIUM, or HIGH when called). The text report labels it
  `[severity_unpublished]`, the PDF lists it under Data-quality Notes, and its
  warnings collapse into their own summary line.

#### Time bombs explained in every report; PDF reports now list them

- **The text report, PDF report and weekly security issue now say what a
  time bomb is:** any dependency, direct or transitive and not confirmed as
  test-only or outside the build, that is archived upstream or has a CISA
  KEV-listed or CRITICAL CVE. An archived
  module cannot be fixed by updating — it has to be replaced or removed — and
  age alone does not make a time bomb (modules with no recent release are
  counted under Unmaintained).
- **PDF reports now have a Time Bombs section** under Key Findings, listing
  each one's kind, module and detail. Previously the PDF named only the
  headline rule on its cover (`Driver: archived_floor`), not the module
  behind it.
- **The weekly security issue explains its stale-dependency check.** It could
  read "Stale dependencies (>90d): false" next to an archived time bomb — for
  example `github.com/google/go-cmdtest` in 2026-W40. That is not a
  contradiction: the stale check covers direct dependencies that have a newer
  version available, pinned more than 90 days ago, and `go-cmdtest` is
  transitive with no newer release. Both sections of the issue and the job
  summary now carry a note stating their scope, and the renderer has bats
  tests in CI.

#### Standard-library vulnerabilities in JSON and PDF reports

- **JSON and PDF reports now include standard-library vulnerabilities,** which
  only the text report listed before. JSON gains a top-level
  `stdlib_vulnerabilities` array after `dependencies` (omitted when there are
  none); the PDF gains a "Standard Library Vulnerabilities" section before the
  vulnerability ID alias appendix, and that appendix now covers
  standard-library aliases. Entries carry the same evidence as a dependency
  vulnerability (`reachability`, `call_path`, `call_trace`, `called_symbols`,
  EPSS and KEV fields in JSON; severity, fix version, `Reached via:` and
  `Vulnerable symbols called:` in the PDF), except that JSON never sets
  `severity_scored`.
- **All three reports list them in the same order, sorted by advisory ID**,
  instead of govulncheck's finding order. The text report's
  `STDLIB VULNERABILITIES` section now also prints `Reached via:` and, when more
  than one symbol is called, `Vulnerable symbols called:`.
- **They are not scored.** The scorer does not read standard-library
  vulnerabilities, so they are not counted in `summary` and change no risk
  score or the headline.

### Bug Fixes

- **A failed severity lookup on one alias no longer makes the grade Pending when another alias of the same vulnerability
  supplies the severity.** When advisories are merged, `SeverityLookupFailed` is kept only while the merged severity is
  still unknown.
- **A scan that needs a newer Go than unisupply was built with now says so.** govulncheck runs in-process, and the loader's
  "file requires newer Go version go1.27 (application built with go1.26)" error was all a user saw. The scan now stops with
  "this unisupply was built with go1.26.9 and cannot scan code that needs go1.27; rebuild unisupply with go1.27 or
  newer", which is the `vulnerability_scan` Pending reason. New exported `scanner.CheckToolchain(scanGo)` lets gorisk check
  at startup. Only a newer Go minor (language) version is refused: a newer patch release or release candidate of the same
  minor version (go1.27.1 to go1.27.2) loads fine and is scanned.
  A scan that failed (including this refusal) is also named in the report `warnings`, for a module with no dependencies
  too, not only on stderr.
  The v0.7.0 release binaries are built with Go 1.26.9. To scan code that needs go1.27, install unisupply with Go 1.27
  or newer (`go install github.com/unidoc/unisupply/cmd/unisupply@v0.7.0`).
- **The module's own advisories count toward the known-exploited check.** With no CISA catalog (not even a copy under 30
  days old), a called advisory on the module itself with a CVE is now Pending `known_exploited`, like a dependency's, instead
  of a D.

- **`--require-github-token` now fails (exit 3) when GitHub rejects the
  token, and a rejected token is reported as such.** The flag used to check
  only that a token was present. GitHub answers 401 to every request that
  carries a bad token, so every maintainer lookup failed individually, the scan
  exited 0, and the only signal was the same "GitHub API unauthenticated"
  warning a run with no token produces. The token is now validated once, after
  the dependency graph is resolved and before any scanner runs, with a request
  to `api.github.com/rate_limit`; a network error or 5xx is retried twice with
  a short backoff. A rejected token exits 3 under the flag; without it the scan
  warns (`GitHub token rejected (401) — continuing unauthenticated`), records
  the same notice in the report's warnings (so it also shows under
  `--progress none` and in JSON output), and drops the token so the scanners
  really run unauthenticated. The GitHub rate-limit warnings then say the token
  was rejected instead of asking for `GITHUB_TOKEN`. Under the flag, a token
  that could not be validated (a network error, or any response other than 200
  and 401, such as 403, 429 or 5xx) also exits 3, with a different message;
  without the flag it warns and keeps the token. Ctrl-C during the check exits
  as an interrupted run, not as a token failure. `--offline` skips the check,
  and the warning no longer says the requirement is "satisfied". The new
  request is listed in the README network-contract table.
- **The same scan now produces the same report.** Several lists were built
  from Go maps, so their order changed from run to run: the takeover
  candidates in the text, JSON and PDF reports, CI/CD findings (workflow jobs
  and step `env`/`with` secrets), and the CycloneDX `dependsOn` lists and SPDX
  package list. In SPDX, each `SPDXRef-Package-N` ID could point at a
  different module on every run. All of these are now sorted (takeovers and
  SBOM entries by module path, CI jobs by job ID), so SPDX package IDs follow
  module-path order. Fields that are meant to differ per run (timestamps, the
  CycloneDX `serialNumber`, the SPDX `documentNamespace`) are unchanged.
- **Modules from the same GitHub repository now report their own
  sub-dependency count.** Modules such as `foo/bar` and `foo/bar/v2` shared
  one cached maintainer record, so "Pulls in N sub-dependencies" (text) and
  `sub_dependencies` (JSON) showed the same, last-written count for all of
  them, and that count changed from run to run.
- **The takeover list names each repository once**, sorted by owner/repo.
  Several modules from one repository used to produce identical rows.
- **The CI/CD write-all permissions finding names unnamed jobs by their job
  ID.** A job without a `name:` key was reported as "Job '' has write-all
  permissions".
- **Test-only classification could never report a test-only module (#135).**
  It compared `go list all` with `go list -test all`, which list the same
  modules, so no module was ever marked test-only and every test-only discount
  was inactive. For a `go.mod` below go 1.16 it also counted modules used only
  by the tests of your dependencies as production: `gopkg.in/check.v1` drove the
  headline of `spf13/cobra` this way. Modules are now classified from
  `go list -deps ./...` and `-deps -test ./...`.
- **Classification failed outright for repositories that `//go:embed` a
  directory that is not in the checkout.** A build output such as `web/dist` is
  usually gitignored, so a fresh clone made `go list` exit with `pattern
  web/dist: no matching files found` and every dependency went unclassified. The
  listing now tolerates per-package errors that do not hide a module, and a scan
  note names the failing package. Notes are shown apart from the scan
  limitations (text report heading "SCAN NOTES", JSON `notes`) because they do
  not make the results incomplete. Errors that do hide a module (an import no
  module provides, a missing `go.sum` entry) still make that platform
  unavailable instead of producing a wrong answer.
- **Platform-specific dependencies were unclassified (#135).** A module imported
  only on another operating system, such as `mousetrap` on Windows, was in
  neither list on a macOS or Linux host. It is now classified as production and
  its `platforms` are reported.
- **The module named as the p95 headline driver was arbitrary when several
  modules had the same score.** It now follows module-path order, and
  `tied_with` reports the tie.
- **Maintainer data was lost for renamed GitHub repositories.** GitHub answers a
  renamed or transferred repository with a redirect, which the scanner treated
  as an error. It now follows one redirect on `api.github.com` and reports the
  repository under its canonical name.
- **The "maintainer data unavailable" warning blamed a missing token when the
  GitHub API had returned errors.** The warning now says "GitHub API error" (or
  "rate-limited or errored" when both happened), so a user who did set a token
  is not sent after a fix that cannot work.
- **A GitHub 429 without `X-RateLimit-Remaining: 0` was reported as an API
  error.** GitHub sends some 429s, such as secondary rate limits, without that
  header. The maintainer scanner counted a 429 as a rate limit only when the
  header said `0`, so those responses were reported as "GitHub API error" and
  the `GITHUB_TOKEN` hint never appeared. Any 429 now counts as rate-limited. A
  403 still counts only with `X-RateLimit-Remaining: 0`; without it, a 403 is a
  permission error. When a token was used, the rate-limit warning no longer
  asks for `GITHUB_TOKEN`; it says the token's quota or a secondary rate limit
  was reached.
- **Standard-library vulnerabilities depended on the directory unisupply was
  started from.** govulncheck runs with `-C <project>`, but `-C` only moves
  package loading: the Go version it matches standard-library advisories
  against and the GOROOT it makes standard-library file positions relative to
  came from the launch directory. One module reported 13, 65 and 46
  standard-library vulnerabilities from three directories using go1.26.8,
  go1.24.1 and go1.26.0; only the run that matched the project's own toolchain
  (46) was right. unisupply now runs `go env GOVERSION GOROOT` in the project
  directory and passes `GOVERSION` to govulncheck, so the result follows the
  project's toolchain wherever unisupply is run. A `GOVERSION` already set in
  the environment is respected. Standard-library file positions in `call_trace`
  are rebased onto the project's GOROOT (for example `src/sync/once.go`)
  instead of being dropped. If the project's toolchain cannot be resolved,
  govulncheck's previous behavior is kept and the report warns "could not
  resolve the project's Go toolchain (...); standard-library vulnerabilities
  are checked against the Go version of unisupply's working directory". Risk
  scores are not affected: the scorer does not read standard-library
  vulnerabilities.

### Security Patches

- **Built with Go 1.26.9 instead of 1.26.8**, clearing 13 standard-library
  advisories that affect v0.6.0 binaries. govulncheck reports 9 of them as
  reachable from unisupply's HTTP client: GO-2026-6603, GO-2026-6605,
  GO-2026-6607, GO-2026-6608, GO-2026-6610, GO-2026-6611, GO-2026-6612,
  GO-2026-6613, GO-2026-6617. The other 4 are imported or module-level only:
  GO-2026-6599, GO-2026-6600, GO-2026-6604, GO-2026-6609. Building from source
  now needs Go 1.26.9 or newer, and CI tests against Go 1.26.9 and 1.27.1.
- Upgraded `golang.org/x/net` `v0.59.0` → `v0.60.0` (GO-2026-6603,
  GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6617). unisupply does not
  call the affected HTTP/2 code; it is pulled in through UniPDF's use of
  `x/net/html/charset`.

## [0.6.0] - 2026-09-29

### New Features

- **`--offline`: a scan that makes no outbound requests.** Enforcement is
  structural, not advisory: in-process requests are refused before a socket is
  opened — covering `golang.org/x/vuln` and UniPDF, which bypass the shared
  scanner client — and `go` subprocesses run with `GOPROXY=off`, cleared
  `GOPRIVATE`/`GONOPROXY`/`GONOSUMDB`, and `GOSUMDB=off` so they read only the
  local module cache. Clearing the private-module patterns is required: the
  toolchain matches them ahead of `GOPROXY=off`, so a `GOPRIVATE` entry would
  otherwise permit a direct VCS fetch, and the checksum database falls back to
  contacting its host directly. Combine with `--network-log` to observe every
  refusal. Degraded axes are marked rather than fabricated: the vulnerability
  scan is skipped with a warning naming the missing local vuln DB mirror,
  maintenance reports the count of unmeasured modules, and go.sum verification
  reports `UNKNOWN (offline — verification skipped)` instead of a failure.
  Degraded scans now also print a `SCAN LIMITATIONS` block in text output, so
  an incomplete scan no longer renders identically to a clean one.
  `--offline` is rejected alongside `--trust-index-url` and `--format pdf`
  (both require the network); it warns but proceeds alongside
  `--require-github-token`. A documented air-gapped vuln-DB mirror workflow is
  not yet included, so offline scans report no vulnerabilities.

- **`--network-log`: observable outbound requests.** Prints every outbound
  HTTP request to stderr as `NET <METHOD> <host> <purpose> → <status>
  (<bytes>, <duration>)`, so the network contract documented in the README can
  be verified rather than trusted. Each of the scanner call sites carries an
  explicit purpose label (`maintainer:contributors`, `threatintel:kev`, …);
  traffic from dependencies that bypass the shared client — `golang.org/x/vuln`
  reaching `vuln.go.dev`, UniPDF reaching `cloud.unidoc.io` — is labeled from
  its host. Child-process traffic (`go mod graph`, `go list`, `go mod verify`)
  cannot be intercepted per-request and is reported as a `NET SUBPROCESS`
  lifecycle line. Logging goes to stderr only, so `--format json` output stays
  clean; nothing is installed and no behavior changes when the flag is off.

- **`go.mod` replace/exclude directive audit (Integrity scanner).** Every
  `replace` directive is classified as a version-pin (LOW), local-path
  override (MEDIUM), or redirect to a different module (HIGH); `exclude`
  directives render as INFO findings. A HIGH-severity redirect floors the
  project headline into the HIGH band (`integrity_floor` candidate) and adds
  a `replaced` risk factor to the affected dependency. Fully offline — no
  network calls. New `forbid_replace_redirect` policy rule (enabled in the
  strict preset) fails CI when a redirect replace is present.
- **go.sum completeness check and go.sum verification (Integrity scanner).**
  A project with requirements but no go.sum gets a HIGH `gosum_missing`
  finding; direct dependencies with no go.sum entry get a MEDIUM
  `gosum_incomplete` finding (direct-only by design — module graph pruning
  makes transitive entries legitimately optional; skipped entirely when
  `vendor/modules.txt` is present).
  Checksum verification shells out to `go mod verify` — checking the local
  module cache against the checksums pinned in go.sum, honoring
  `GOPRIVATE`/`GONOSUMDB` — and is reported as `gosum_verified`
  (`"true"`/`"false"`/`"offline"`/`"skipped"`) in all output formats. A
  confirmed mismatch (integrity markers in the verify output) produces a
  CRITICAL `gosum_mismatch` finding and floors the project headline into the
  CRITICAL band; UNKNOWN states — offline mode, cancellation, cold cache
  without network, missing toolchain — are never treated as failures. New
  `require_gosum_verified` policy rule (enabled in the strict preset) fails
  CI on a confirmed mismatch.
- **Pseudo-version pin audit (Integrity scanner).** Every resolved dependency
  pinned to a pseudo-version (`v0.0.0-YYYYMMDDHHMMSS-abcdefabcdef`, including
  the pseudo-version-on-top-of-a-tag form) is flagged using
  `golang.org/x/mod/module.IsPseudoVersion` — fully offline. Direct
  dependencies get MEDIUM severity (+4 per-dependency penalty), transitive
  dependencies get LOW (+2), and confirmed test-only dependencies get INFO
  with no score impact. Distinct from the AI-generated-code scanner's
  `pseudo_version_only` indicator, which fires on zero-tagged-releases-ever
  rather than the currently pinned version — both signals can coexist, and
  their pseudo-version-related contributions sum to at most 5.5 (1.5 from the
  `pseudo_version_only` indicator plus 4 from this bonus); the aigen bonus as
  a whole can be larger. Pseudo-version findings are per-dependency
  risk factors only and never drive the project headline. New
  `forbid_pseudo_versions` policy rule (enabled in the strict preset) fails
  CI on any non-test-only pseudo-version pin.
- **Threat-intel enrichment (EPSS + CISA KEV).** Every CVE now carries EPSS
  (exploitation probability from FIRST.org: `epss_score`, `epss_percentile`,
  `epss_date`) and CISA KEV status (confirmed exploited in the wild: `in_kev`,
  `kev_date_added`, `kev_known_ransomware`). Scoring uses both to refine the
  headline: EPSS ≥ 0.5 promotes a CVE one severity tier, KEV membership forces
  CRITICAL (neither resurrects a CVE dropped by the reachability or test-only
  downgrades). Per-dep scores gain an EPSS bonus (`max_epss × 15`) and any
  KEV-listed CVE floors its dependency at 76/CRITICAL. KEV-listed CVEs appear
  as `kev` entries in TIME-BOMBS, and a hidden-risk warning is emitted when a
  KEV or EPSS ≥ 0.9 CVE was downgraded by static analysis. Adds two network
  endpoints (`api.first.org`, `www.cisa.gov`), both best-effort with 24h
  on-disk caches — threat-intel unavailability never fails a scan.

### Improvements

#### Minimum Go version is now 1.26

- **Building from source requires Go 1.26.** The `go` directive moves from
  1.25.10 to 1.26.8, and release binaries are built with Go 1.26.8. Go 1.25 no
  longer receives upstream security fixes, and the `golang.org/x/crypto` fixes
  listed under Security Patches require Go 1.26. With the default
  `GOTOOLCHAIN=auto`, `go install` on an older Go downloads the required
  toolchain automatically; with `GOTOOLCHAIN=local` it stops with a
  `requires go >= 1.26.8` error. Prebuilt release binaries are unaffected.
- CI now tests against Go 1.26.8 and 1.27.1.

#### PDF reports now use UniPDF v5

- **The archived `github.com/gorilla/i18n` is no longer compiled into the
  binary.** UniPDF v3's line breaking imported it, so every v0.5.0 binary
  shipped code from an archived repository, pinned at a 2015 commit. PDF generation
  moves from `github.com/unidoc/unipdf/v3` v3.69.0 to
  `github.com/unidoc/unipdf/v5` v5.1.0, which no longer depends on it; the
  change is import paths only. Report output is unchanged: on the same scan
  target, six of seven pages have byte-identical content streams, and the
  seventh differs only in the order of the takeover-candidate rows, which
  already varies between runs of the same binary.
- Compiled in: removed `github.com/gorilla/i18n` and
  `github.com/gabriel-vasile/mimetype`; added `github.com/unidoc/typesetting`
  (Unlicense OR BSD-3-Clause, used under BSD-3-Clause) and
  `github.com/h2non/filetype` (MIT). In the module graph only: removed
  `github.com/trimmer-io/go-xmp`; added `github.com/unidoc/go-xmp` and
  `github.com/go-text/typesetting-utils`. UniPDF's own dependencies also move
  (`unidoc/unichart` v0.5.2, `unidoc/freetype` v0.2.5, `unidoc/pkcs7` v0.3.0).

#### Reports: one vulnerability identifier, and one warning per failure mode

- **The Go advisory ID is now the single identifier in text and PDF output.**
  Advisory lines rendered `GO-2026-5026 (CRITICAL) [required] — CVE-2026-39821`
  while the stdlib section rendered `GO-2026-4970 Summary (CVE-2026-39822)` —
  two conventions in one report, with no way to tell which was authoritative.
  Both now carry the `GO-*` ID alone: it is the only identifier govulncheck
  guarantees, since some advisories have no CVE. CVE and GHSA identifiers move
  to one place — a `VULNERABILITY ID ALIASES` section in the text report and an
  "Appendix: Vulnerability ID Aliases" table in the PDF. JSON is unchanged; its
  `aliases` array is the machine contract, and EPSS/KEV lookups are still keyed
  by CVE internally.
- **An advisory is no longer listed as its own alias.** When govulncheck
  reported no aliases the renderer substituted the ID, producing
  `⚠ GO-2026-5932 (UNKNOWN) [required] — GO-2026-5932`. Alias-less advisories
  are simply absent from the glossary.
- **Repeated severity-lookup failures collapse to one line.** A scan of a
  vulnerability-heavy module emitted 21 near-identical
  `severity lookup failed (OSV/NVD/GitHub) for GO-…` warnings, burying every
  warning that was not a repeat. They now render as a single line naming the
  count and the first five IDs, listing each advisory once — the same advisory
  can be reported under two modules, and the repeat must not inflate the count
  or consume a displayed slot. Nothing is lost: each vulnerability keeps its
  own `enrichment_errors` entry in JSON, and a lone failure still prints as
  itself rather than as a summary of one. The collapse is applied in the
  scanner, so the top-level `warnings` array in JSON output carries the
  summary line too; per-vulnerability `enrichment_errors` is unchanged and
  remains the machine contract for which advisories failed enrichment.

#### The network contract is now integration-tested

- **Documentation drift in the network contract fails the build.** A new
  hermetic integration suite (`test/integration/`) parses the host table out of
  README.md § Privacy and network access, records every host the scanners
  actually contact — through the same `http.DefaultTransport` choke point
  `--network-log` uses — and asserts both directions: no host is contacted that
  the table does not document, and no documented row goes unexercised. Coverage
  is asserted per row rather than per host, so the three separate
  `api.github.com` rows (maintainer, resilience, GHSA enrichment) each have to
  be exercised on their own — one GitHub request cannot stand in for the other
  two. Rows that cannot be driven in-process (`vuln.go.dev`, `cloud.unidoc.io`, the
  user-supplied Trust Index URL) each carry a written reason in the test, so a
  newly added row is a failure until someone drives it or explains why it
  cannot be. The hosts the README promises are never contacted directly
  (`sum.golang.org`, `pkg.go.dev`) are asserted uncontacted, a permanent
  red test proves the allowlist check has teeth, the Trust Index client is
  verified to contact only its configured host, and SECURITY.md's prose
  summary is compared against the table in both directions, so a host dropped
  from the README cannot be left behind in the summary. No request leaves the
  machine: the recorder rewrites each request to a local stub server.
- **SECURITY.md now lists the EPSS and KEV hosts** (`api.first.org`,
  `www.cisa.gov`), which were added to the README table with the threat-intel
  scanner but never to the prose summary — the first drift the new test caught.

#### Scoring: unmeasured axes no longer counted as measured

- **An unavailable axis is excluded from the weighting, not scored.** Its weight
  now leaves both the numerator and the denominator, and the surviving weights
  renormalize to 1.0 — the treatment the maintainer axis already received, now
  applied to vulnerabilities (0.40) and maintenance (0.25) as well. Previously a
  skipped vulnerability scan scored the 40% axis as clean, indistinguishable from
  a verified-clean project, and a failed maintenance lookup was scored with a
  hard-coded unknown constant of 30. Depth and maturity are never excludable, so
  the denominator floors at 0.25. An online scan whose vulnerability scan
  *succeeds* is unaffected; one where govulncheck **fails** is now treated as
  unmeasured too, so a CI job with a flaking govulncheck will see the 40% axis
  excluded and the headline reported as `UNKNOWN` where it previously received a
  band. That is deliberate — a failed scan found nothing because it never
  looked — but it is a behavior change for consumers that gate on the level.
  Policy exit codes are unchanged: the preset ceilings (strict 70/50, moderate
  85/70) sit far above the scores a degraded scan can reach.
- **The headline reports `UNKNOWN` when the vulnerability scan did not run.**
  Three of the five headline candidates are CVE-derived and score 0 without
  vulnerability data, which left the headline resting on dependency-graph
  position and version scheme alone — enough to promote UniOffice from LOW to
  MEDIUM in an offline scan that performed no CVE check. `overall_risk_level` is
  now `UNKNOWN` with a new `headline_unscored_reason` field; the numeric score is
  still reported and labelled indicative. Per-dependency `risk_level` is
  unchanged.
- **JSON breakdowns distinguish "nothing found" from "nothing looked."**
  `vuln_score`, `maintenance_score` and `maintainer_score` serialize as `null`
  when the axis was unavailable, alongside new `measured_weight` and
  `excluded_axes` fields. Text reports print effective weights, so the breakdown
  multiplies out to the score it sits next to.
- Project warnings now name every unmeasured axis — maintenance and resilience
  join the existing maintainer warning, and resilience unavailability discloses
  that AI-generated-code detection is disabled with it.
- **Resolver degradations reach the report, not just stderr.** A cold cache makes
  `go mod graph` fail, and the go.mod/go.sum fallback flattens the graph so every
  transitive dependency collapses to depth 1 — which feeds the depth axis
  directly. `go list` failing leaves the test-only classification unavailable for
  every dependency, disabling the test-only discount. Both now appear in
  `warnings` and the `SCAN LIMITATIONS` block.
- **Maintenance failures on online scans are reported too.** Previously only the
  offline branch recorded a warning, so a module-proxy outage produced a report
  that looked complete. The wrapped error is deliberately not carried into the
  report — it embeds a proxy URL, i.e. a module path — so the warning names the
  cause and the scorer supplies the affected module count.
- `scanner.ScanVulns` now returns whether govulncheck actually analyzed the module
  graph. Most govulncheck failures surface as a warning with a nil error, so
  availability could not be inferred from the error alone — a failed scan was
  being scored as clean.
- **AI-generated-code detection reports when it did not run.** Every indicator it
  uses derives from the module's first-release date, so without that date the
  module is unexamined, not cleared — but both outcomes produced `risk_level:
  "none"` with score 0 and were dropped from the results, making an unexamined
  module indistinguishable from a cleared one. `AIGenRisk` gains a
  `data_available` field, `AIGenScanner.ScanAll` returns warnings naming the
  affected module count, and the README no longer lists AI-gen among the scanners
  `--offline` leaves intact (it never worked offline — resilience data, which it
  depends on, comes from the module proxy).

- The CRITICAL verdict text "could be actively exploited" is now
  evidence-gated: it appears only when a CVE is KEV-listed or has EPSS ≥ 0.5;
  otherwise severity-based wording is used.
- PDF reports sort each dependency's vulnerabilities KEV-first, then by EPSS
  descending; text and PDF reports show `[EPSS NN%]` and `[KEV]` badges per
  CVE.

### Bug Fixes

- **SBOMs no longer report the Go version as the project's own version.** The
  CycloneDX root component's `version` and the SPDX root package's
  `versionInfo` were set to the scanned module's `go` directive — a project
  declaring `go 1.25.10` was described as version `1.25.10` — and the SPDX
  `downloadLocation` pointed at a module-proxy URL built from it that does not
  exist. go.mod carries no version for the main module, so both fields are now
  omitted and the SPDX root `downloadLocation` is `NOASSERTION`. The `go`
  directive is kept as a `unisupply:go_version` property on the CycloneDX root
  component. Dependency entries are unchanged, and the output of both formats
  was validated against the CycloneDX 1.5 and SPDX 2.3 JSON schemas.
- **The weekly security workflow now reports reachable vulnerabilities.** It
  ran `govulncheck -format json`, which exits 0 whatever it finds, so the job
  summary's govulncheck badge always read "0 — no vulnerabilities" and a
  reachable vulnerability could never file the weekly issue on its own. On Go
  1.25.10, text mode reported 7 reachable standard-library vulnerabilities
  while the badge showed 0. The exit code is now recovered from the JSON
  findings by `.github/scripts/govulncheck-exit-code.sh`, which has bats tests
  in CI.
- Policy files with unknown or misspelled rule keys are now rejected at load
  time instead of silently ignoring the rule.
- **`low_resilience` no longer fires on missing resilience data.** The risk
  factor was gated on `resilience.Score < 30` without checking
  `DataAvailable`, so a module whose release history could not be fetched —
  leaving the whole struct zero-valued, and its score therefore 0 — was
  flagged as low-resilience on the strength of data that was never collected,
  and charged up to 6 points for it. Both the factor and the bonus now require
  `DataAvailable`, as does the matching explanation line in text reports.
  Affects any scan where the module proxy is unreachable or rate-limits.
- **PDF reports no longer print a literal `##` in CI/CD subheadings.** The
  "CI/CD" and "Build files" subheadings of the CI/CD Risk Assessment section
  rendered as `## CI/CD` and `## Build files` — a Markdown marker the PDF
  printed as text.

### Security Patches

- **Built with Go 1.26.8 instead of 1.25.10**, clearing 12 standard-library
  advisories that affect v0.5.0 binaries. govulncheck reports 7 of them as
  reachable from unisupply's code — GO-2026-5026, GO-2026-5037, GO-2026-5039,
  GO-2026-5856, GO-2026-5972, GO-2026-6090, GO-2026-6218 — and the other 5 as
  imported or module-level only: GO-2026-4970, GO-2026-5038, GO-2026-6088,
  GO-2026-6089, GO-2026-6091.
- Upgraded `golang.org/x/crypto` `v0.53.0` → `v0.57.0` (GO-2026-6303,
  GO-2026-6354, GO-2026-6355, all in `x/crypto/ssh`, which unisupply does not
  import).
- Upgraded `golang.org/x/mod` `v0.37.0` → `v0.41.0` (direct dependency;
  GO-2026-6179, GO-2026-6180 in `x/mod/sumdb`, which unisupply does not import).
- Upgraded `golang.org/x/text` `v0.38.0` → `v0.42.0` (GO-2026-5970) and
  `golang.org/x/image` `v0.43.0` → `v0.46.0` (GO-2026-6222).
- Upgraded `golang.org/x/vuln` `v1.5.0` → `v1.8.0` (direct dependency), and
  `x/net`, `x/tools`, `x/sync`, `x/sys`, `x/term`, `x/telemetry` to current
  releases.
- Self-scan policy gate (`.github/security-policy.json`): 6 violations in the
  2026-09-21 weekly security scan → 0.
  One advisory remains with no upstream fix: GO-2026-5932 (`x/crypto`), which
  govulncheck reports as not reachable from unisupply.

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

[Unreleased]: https://github.com/unidoc/unisupply/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/unidoc/unisupply/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/unidoc/unisupply/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/unidoc/unisupply/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/unidoc/unisupply/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/unidoc/unisupply/releases/tag/v0.4.0
