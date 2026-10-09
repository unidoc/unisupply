# Changelog

All notable changes to `unisupply` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- Add new entries here as they land on `development`. -->

### New Features

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

### Bug Fixes

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

[Unreleased]: https://github.com/unidoc/unisupply/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/unidoc/unisupply/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/unidoc/unisupply/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/unidoc/unisupply/releases/tag/v0.4.0
