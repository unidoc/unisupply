# Scanners

> **Grading v2.** The published result is the letter described in [grading.md](grading.md); policy gates read the
> letter. This page describes the scanners, their data and their limits, and what each signal does to the grade. The
> scorer's old 0-100 risk score and headline are not published in any output; what is left of them is kept short under
> [Internal scorer (not published)](#internal-scorer-not-published) at the end.

This document describes the scanners `unisupply` runs and how their signals reach the grade. It is the reference for
the scanners; if the code in `pkg/scanner` and this document disagree, the code wins, so please open a PR fixing this
file.

## Scanners

| Scanner          | What it checks                                             | Data source                |
| ---------------- | ---------------------------------------------------------- | -------------------------- |
| Vulnerability    | Known CVEs (call-graph-aware via `govulncheck`)            | Go vuln DB (vuln.go.dev)   |
| Maintenance      | Last release, default-branch activity, archive status, deprecation, retraction | Go Module Proxy (GitHub repository and commits APIs for archive status and as a fallback) |
| Maintainer       | Contributors, bus factor, activity, org verification       | GitHub API                 |
| Typosquatting    | Levenshtein-similarity to ~75 well-known modules           | Built-in list              |
| Resilience       | Release cadence, governance files, version-scheme          | GitHub API                 |
| CI/CD            | Action pinning, permissions, secret exposure               | `.github/workflows/*.{yml,yaml}` |
| Build files      | Unpinned Docker images, `curl \| bash` patterns            | Dockerfile, Makefile, *.sh |
| Trust Index      | Curated trust scores (optional)                            | `unitrust` API             |
| Integrity        | `go.mod` `replace`/`exclude` directive audit, `go.sum` verification, pseudo-version pin audit | `go.mod`/`go.sum` (offline) |

The AI-generated-code heuristic no longer runs and nothing from it is published.

A repository that GitHub has renamed or transferred answers with a redirect.
The Maintainer scanner follows one hop, on `api.github.com` only, and reports
the repository under its canonical name; any other redirect target is treated
as an error. When maintainer data cannot be collected, the scan warning names
the cause: an unauthenticated or rate-limited GitHub API, or an API error.

The CI/CD and Build-files scanners are off by default; enable them with
`--scan-workflows` (workflow files `*.yml` and `*.yaml` only) or `--scan-ci`
(workflows + Dockerfile + Makefile + shell scripts). The Trust Index scanner
activates when `--trust-index-url` is supplied.

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
the strongest path is kept, so the choice does not depend on govulncheck's
output order. A path whose only purpose is formatting an error or a string (its
sink or an intermediate frame is a method named `Error` or `String`, or it
passes through package `fmt` or `log`) loses to any path that does not; among
paths of the same kind the shortest wins, ties broken alphabetically. When every
path only formats a message, the shortest is kept as before. The path is evidence that the code is on
an execution path, not proof that the vulnerability is exploitable (see the
caveat below).

`condition` is one short sentence derived from the chosen path's frame names
only, for example `reached through github.com/gin-gonic/gin.Context.Render`: the
first frame outside the project's own code (a `project` frame is required, so it
is absent when govulncheck emitted no `SBOM` message or the path starts inside a
dependency). It names a call, never a configuration, and is evidence rather than
a promise of exploitability.

`call_trace` carries the same path with a source position per entry. It is
index-aligned with `call_path` and has the same length; each object holds
`name`, `module`, `version`, `file`, `line`, `column`, `project` and `elided`,
all omitted when empty. The cut slot is `{"elided": true}` where `call_path`
has `"..."`. Ties between equally short paths are broken on the path string,
then on the frame positions, so the selected trace does not depend on
govulncheck's output order.

- **Position meaning.** For every frame except the last, `file:line:column` is
  the call that frame makes; for the last entry, the vulnerable function, it is
  the function's declaration. Because the path is condensed, a kept frame's
  position can point at a call to a frame that was dropped.
- **Files are module-relative.** `file` is relative to the root of that frame's
  own module (for the standard library, relative to the project's GOROOT, for
  example `src/sync/once.go`), so it is only meaningful together with `module`
  and `version`. Standard-library vulnerabilities are matched against the
  project's toolchain, the Go version `go env` reports in the project
  directory, not the directory unisupply is run from. When govulncheck reports an
  absolute path, or one outside the module (`../...`), `file` is dropped so a
  shared report does not expose the scanning machine's layout; `line` and
  `column` are kept.
- **`project`.** True when the frame's package is one of govulncheck's scan
  roots, as listed in the `SBOM` message of its JSON stream. A govulncheck that
  emits no `SBOM` message leaves `project` false on every frame.

`called_symbols` lists the vulnerable symbols of every called finding for that
advisory in that module, sorted and without duplicates. govulncheck emits one
finding per vulnerable symbol while `call_path` keeps only one path, so this is
where the other symbols remain visible. It holds at most 20 entries, the first
20 in sorted order.

The text and PDF reports show this under each called finding as
`Reached via: example.com/u1repro.main (main.go:13) → golang.org/x/crypto/ssh/agent.keyring.Add`.
`(file:line)` appears only on `project` frames, `...` marks a cut, and a
`Vulnerable symbols called: a, b` line follows when there is more than one
symbol. The PDF separates frames with ` > ` because its standard font has no
arrow glyph.

There is no call-site count. govulncheck emits one representative call stack
per vulnerable symbol and visits each function at most once, so the number of
places that call the vulnerable code is not in its output; any number derived
from it would be a lower bound that reads like an exact count. Neither
`call_trace` nor `called_symbols` affects scoring or policy.

#### Grade effect

Reachability picks the column of the vulnerability table in [grading.md](grading.md#vulnerability-score):

- `called` (or absent, or not determined): scored as called. The finding says when the tier was assumed.
- `imported`: scored lower and capped at 50, so imported code alone can reach C but never D or F.
- `required`: the module is in the graph but no package of it is built. The finding is shown and **not graded**.

A confirmed test-only row halves the vulnerability score (capped at 50), and a module confirmed outside the build is
graph-only whatever the reachability of its findings says. An unknown build classification never discounts.

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

### Standard-library vulnerabilities in reports

Vulnerabilities in the Go standard library of the project's toolchain (see
`Files are module-relative` above for how the toolchain is chosen) belong to no
dependency, so each report lists them separately, in the same order (sorted by
advisory ID) and with the same evidence as a dependency vulnerability:

- **Text report:** the `STDLIB VULNERABILITIES` section, with `Fixed in:`,
  `Reached via:` and, when more than one symbol is called,
  `Vulnerable symbols called:` lines.
- **JSON report:** a top-level `stdlib_vulnerabilities` array after
  `dependencies`, omitted when there are none. Entries have the shape of a
  dependency's `vulnerabilities` entries, including `reachability`,
  `call_path`, `call_trace`, `called_symbols` and the EPSS and KEV fields, but
  never `severity_scored`.
- **PDF report:** a "Standard Library Vulnerabilities" section on its own page,
  before the vulnerability ID alias appendix, with the same per-vulnerability
  lines as a dependency block.

They are graded as a row named `stdlib` (see [grading.md](grading.md)) and are not
counted in the `summary` counts.

### Vulnerability identifiers in report output

Human-facing output — text and PDF — identifies every advisory by its **Go
advisory ID** (`GO-YYYY-NNNN`). That is the only identifier guaranteed to
exist: govulncheck is the scan source, and not every advisory has a CVE (some
carry only a GHSA alias, and fresh Go advisories may carry none at all). A
CVE-first scheme would leave those findings without a name.

CVE and GHSA identifiers are not dropped — they are collected into one place:

- **Text report:** a `VULNERABILITY ID ALIASES` section between the stdlib
  vulnerabilities and the summary.
- **PDF report:** an "Appendix: Vulnerability ID Aliases" table, which also
  covers standard-library advisories.

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
never reported as unscored. The grade treats both the same: an
advisory with no published severity is scored as MEDIUM and the letter is marked
estimated (`C*`) when it rests on that estimate. Only the label differs; the text report marks the two cases
`[enrichment_failed]` and `[severity_unpublished]`, and the PDF lists unscored
advisories in a separate Data-quality note. Unscored advisories are rechecked
after one hour.

**NVD pacing and retries.** NVD lookups are paced process-wide: at most 5
requests per 30 seconds without a key (one every 6.2 s) and 50 with one (one
every 0.7 s). A request answered 429, 403 or 5xx, or lost to a network error, is
retried up to 3 times, waiting for the `Retry-After` header (seconds or an HTTP
date, at most 60 s) or backing off 5, 10 and 20 s. All this waiting is bounded
by one budget of 3 minutes per scan; once it is used up the remaining NVD
lookups fail at once, without waiting. A lookup that still fails stays
`enrichment_failed: true` and `enrichment_errors` names the cause (`NVD rate
limited (HTTP 429)`, `NVD HTTP 503`, `NVD network error`). When the cause is
rate limiting the warning reads `severity could not be looked up (NVD rate
limit: set NVD_API_KEY) for N advisories`. A failure caused by rate limiting is
cached for 2 minutes, other failures for 1 hour. NVD's CVSS v3.1, v3.0 and v4.0
metrics all count, whoever published them: NVD's own (Primary) is preferred, but
a CNA's (Secondary) metric is used when it is the only one, as on a fresh
advisory that is still "Awaiting Analysis".

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

### The module's own advisories

A dependency's advisories come from govulncheck, which does not check the module
it starts from. The module's own advisories are therefore read straight from
OSV: one `POST https://api.osv.dev/v1/query` with the module path (ecosystem
`Go`) and its **version**, following `next_page_token` for at most 10 pages.
OSV answers with the advisories that affect exactly that version.

- The version is required. A query without one returns the advisories of every
  version of the module, so an empty or malformed version, or an invalid module
  path, is an error and no request is made.
- Withdrawn advisories are skipped.
- Each advisory becomes a vulnerability record like a dependency's: `id`,
  `aliases`, `summary`, `published_at`, `fixed_version` (the lowest fixed
  version above the queried one, among the ranges that name this module),
  `fix_published_at` and `days_unpatched` as for dependencies, and
  `affected_packages` (the import paths the advisory names, sorted, without
  duplicates). `reachability` is left empty: the grade assumes the module's own
  advisories are called.
- Severity comes from the record (`database_specific.severity`, then a CVSS v3
  vector), then the [resolution order](#severity-resolution-order) above, with
  the same `UNKNOWN`, `unscored` and `enrichment_failed` meanings. EPSS and KEV
  are applied as for dependencies.
- A failed lookup (transport error, non-200 status, unparseable or oversize
  response, more than 10 pages) is an error, never an empty list: an empty list
  means OSV answered and nothing affects that version. The caller reports the
  module's own advisories as pending. Severity, EPSS and KEV failures are
  best-effort warnings and never fail the lookup.
- `--offline`: no request is made and the lookup returns an error.

The response read is capped at 8 MB per page and the whole lookup at 30 s.
`--network-log` labels these requests `selfadvisory:osv`.

### Fix-release dates

`fix_published_at` is the advisory's publication date, which can be days before
the fixed version exists. `fix_released_at` is the better date: the **later** of
`fix_published_at` and the time the Go module proxy gives the first fixed
version (`GET <proxy>/<module>/@v/<version>.info`, the `Time` field; the module
path and version are escaped as the proxy requires).

`fix_published_at` is an **advisory publication date**, not a fix date. It is set for every finding that has a fixed
version, from the `published` field of the OSV entry govulncheck emits (and by the severity enrichment when that entry has
none), so a finding whose fixed version the proxy cannot date still has a fix date: the advisory's, with source
`advisory`. The fix date is the later of the advisory date and the proxy's time; it is never a date nobody gave.

| `fix_date_source` | Meaning |
| ----------------- | ------- |
| `module_proxy`    | The proxy's time was later than or equal to the advisory's date |
| `advisory`        | The advisory's date was later, or the proxy had no time for that version (404, 410, error, timeout) |
| absent            | Neither is known; `fix_released_at` is absent too |

A vulnerability with no `fixed_version` gets neither field. No date is ever
invented: a failed lookup leaves the advisory's date (source `advisory`), or
nothing. Lookups are de-duplicated per fixed version, run at most 8 at a time
and share one 30 s budget. When `fix_released_at` is set, `days_unpatched` is
counted from it.

For the standard library the fixed version (`go1.26.9`, `v1.26.9` or `1.26.9`;
`go1.21` means `go1.21.0`) is released when the proxy says
`golang.org/toolchain@v0.0.1-go1.26.9.linux-amd64` was; the rule is otherwise
the same. A fixed version that is not a Go release is not looked up.

Both features use only `api.osv.dev` and `proxy.golang.org`, already in the
network contract in the README's "Privacy and network access" table, which
lists these requests as their own rows. `--offline` makes no lookup and leaves
the advisory's date.

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

#### Grade effect

EPSS is shown as data and is **not** an input of the grade. KEV is: a *called* finding on the CISA KEV list scores at
least 76 (F), and a whole-tree rule raises the letter to F on a called KEV finding. A test-only KEV finding lands at C
(the test-only discount halves the score, capped at 50), and a finding in a package that is never imported is shown and
not graded. The text and JSON reports carry a warning when a KEV-listed finding was downgraded by test-only status or
reachability, so the exploitation evidence is not lost behind the downgrade. A KEV-listed finding also produces a
`kev` time-bomb entry. The thresholds are not operator-tunable.

#### Cache and failure behavior

EPSS responses are cached per CVE under `$XDG_CACHE_HOME/unisupply/epss/` and
the KEV catalog (single ~1.5 MB bulk fetch per scan) under
`$XDG_CACHE_HOME/unisupply/kev/`, both with a 24-hour TTL (EPSS scores are
recomputed daily; KEV updates weekly at most). Both lookups are best-effort:
on failure the scan completes with a warning and the fields absent —
threat-intel unavailability never fails a scan. When the KEV catalog cannot be
refreshed after its 24-hour cache has expired, the older cached copy is used
instead if it is at most 30 days old: findings count as checked
(`kev_checked: true`) against that list, each carries `kev_catalog_stale_since`,
and a warning says "CISA KEV catalog could not be refreshed; using the copy from
<date> (N days old)". Only when no catalog was ever cached, or the cached copy is
older than 30 days, is KEV "not available" and `kev_checked` absent (the grade is
then Pending `known_exploited` if a reached finding with a CVE could be on the list).

### Scan details

The vulnerability scan records what it ran with (`scanner.ScanInfo`, `Result.ScanInfo`):
the platform (`goos/goarch`, from `GOOS`/`GOARCH` or the running binary), the Go
version, the govulncheck version and the vulnerability database with its
last-modified time. The govulncheck version is that of `golang.org/x/vuln` in the
binary's build info (govulncheck runs in-process, so its own `scanner_version`
would be unisupply's version); it is left out when the build info does not list it.
The database fields come from govulncheck's leading `config` message; output
without that message leaves them empty.

> **Coverage caveat:** EPSS and KEV apply per-CVE; they do not change which
> CVEs are detected. Coverage is bounded by govulncheck + OSV enrichment, and
> the same static-analysis limits described above apply.

### Maintenance age and deprecation

A project's upkeep does not rest on release tags alone. A repository that is
worked on but rarely tagged would otherwise read as abandoned, so the age
is taken from the newer of two dates:

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
a scan warning. Without activity the release age alone is used, as
before; archived modules are not looked up.

A resolved branch answer, and the latest version's `go.mod` (read for
deprecation), are kept in the on-disk cache for 24 hours, like the GitHub API
responses, so a rerun within the day does not ask again.

The JSON `maintenance` object reports `last_activity`, `months_since_activity`,
`activity_source` (`proxy_branch` or `github_commits`) and `activity_branch`
when activity is known; the text and PDF reports show "Last commit (branch)".
The `unmaintained_1yr` / `unmaintained_2yr` summary counts and the
`no_unmaintained_months` policy rule use the same combined value, so the report
and the policy agree. Age alone never lowers the grade: only archived and
deprecated (including retracted) rows count there, and only up to C.

GitHub's `pushed_at` is **not** used for the age above. It moves on a
push to any branch, Dependabot branches included, so a repository whose default
branch stopped moving years ago can look active. It is reported as
`maintainer.last_commit_date`, and in the text report's maintainer section as
"Last push (any branch)", and it sets `maintainer.activity_pattern`. The grade
reads neither.

**Deprecation.** A module is deprecated when the `go.mod` of its latest version
carries a `// Deprecated:` notice on its `module` directive (the rule `go list
-m -u` and `go get` apply, parsed with `golang.org/x/mod/modfile`), or when the
module proxy answers `@v/list` with 410. The notice usually names the
successor and is reported as `maintenance.deprecation_message`, in the text and
PDF reports and in the `no_deprecated` policy violation. Deprecated, like
archived, is an upkeep state whatever the dates: the maintainers have said to
move off the module, and a recent commit (for example on
`github.com/golang/protobuf`) does not change that. Both count in the grade, but
only up to C (see [grading.md](grading.md#upkeep-score)).

**Retraction.** The same go.mod read (one request, no extra) is searched for
`retract` directives. When the module's **pinned** version, the one in the
dependency graph, falls inside a retracted single version or `[low,high]` range
(semantic-version comparison), the JSON `maintenance` object reports
`retracted: true` and the maintainers' `retraction_message` (the rationale
comment, "" when they gave none). A retracted version reads as deprecated to
consumers, but the scanner does **not** set `deprecated` for it: the two stay
separate evidence, and the grade treats `retracted || deprecated` as one
state. A pinned version that is not valid semver is never reported retracted.

**Unchecked is not clean.** When the go.mod of the latest version cannot be read
(a transport error or non-200 answer, an unparsable file) or the proxy has no
latest version, the scanner sets `mod_check_failed: true` and reports neither
deprecation nor retraction from it. `deprecated: false, retracted: false` then
means "not checked", and the grade treats the module's upkeep as missing data
(Pending) unless the module is archived anyway. The pinned version passed to the
proxy must be a full canonical version (`vMAJOR.MINOR.PATCH[-pre]`, optionally
`+incompatible`); anything else is not requested.

**A module with no tagged release.** A dependency required at a pseudo-version
(for example `github.com/itchyny/go-yaml`) has no tags, and the proxy answers
`@latest` for it with 404 or 410. That is an answer, not a failure: the pinned
version is then taken as the latest. Its `.info` gives the release time and the
origin, `latest_version` is the pinned version (so no "newer release" is
claimed), and deprecation and retraction are read from the pinned version's
`go.mod`. A 5xx, a timeout or any other failure of `@latest` is still a
failure: `mod_check_failed` is set as above.

**Repository and archive status.** The repository behind a module path is
resolved first, from the `Origin` the module proxy records for the latest (else
the pinned) version: the `@latest` and `.info` answers the scan already reads,
so it costs no request. An `https` GitHub origin (`gopkg.in/yaml.v3` ->
`https://github.com/go-yaml/yaml`, `k8s.io/api` -> `github.com/kubernetes/api`)
is reported as `maintenance.repository_url`, and for a `github.com` module path
without an origin it is the repository the path names. The archived flag is then
read from `GET api.github.com/repos/{owner}/{repo}`, the same call the
Maintainer scanner makes, so a vanity path is covered like a `github.com` one.
`maintenance.archived_check` says whether `archived` is an answer:

| `archived_check` | Meaning |
| ---------------- | ------- |
| `checked`        | GitHub answered; `archived` is the flag read |
| `failed`         | The lookup was attempted and did not answer (rate limit, 401/403, 5xx, network error, or 404). `archived: false` here means "not checked", never "not archived". |
| `unsupported`    | The repository is on a host other than GitHub (`go.googlesource.com`, GitLab, ...), which cannot be asked |
| (absent)         | Nothing was attempted: offline, no lookup configured, or no repository known |

A 404 (repository deleted, private, or renamed away without a redirect) is a
definitive answer: `repository_not_found: true`, `archived_check: failed`, and,
in the maintainer data, `unavailable_reason: repo_not_found`. It is asked once,
shared by every module of that repository, and is neither a rate limit nor
counted in the "archived status could not be read" scan warning, which counts
only lookups that failed for another reason. A rename redirect is followed one
hop, on `api.github.com` only, as before.

**GitHub call budget.** Every per-repository GitHub answer (repository record,
contributors, owner profile, latest commit) is cached for the life of the scan
and shared by all modules of the repository, failures included, and the
successful ones are kept on disk for 24 hours as before. Modules from one
repository (`golang.org/x/*` mirrors, `k8s.io/*`, a monorepo's submodules) cost
one request per endpoint, not one per module. A repository costs at most
3 requests (repository, contributors, latest commit; the last only with a
token and only when the proxy cannot answer the activity query), plus one
profile request per distinct owner. The archived check adds nothing for a
repository the maintainer scan already fetched, and one request (the repository
record) for a vanity-path repository. A 404 repository costs one request in
all. The Resilience scanner's governance-file probes (3 `HEAD` requests per
`github.com` module) are separate and not yet cached. Conditional requests
(ETags) are not used.

### Resilience request bounds

The resilience check asks the module proxy (`proxy.golang.org`) for the version
list of each module (`@v/list`, purpose `resilience:version-list`) and for the
release date of versions (`@v/<version>.info`, purpose
`resilience:version-info`). No new outbound call is made; the number of date
requests is bounded:

- at most 24 dates per module: the newest 23 versions and the oldest one (the
  proxy's list is ordered by semver before the cut). The oldest anchors the
  project age; the full list still gives the release count, the stable and
  major-version flags and the version scheme;
- at most 3,000 date requests per scan, shared by all modules, and at most 16 in
  flight at once;
- a module cut by the cap, by the budget or by failed requests reports
  `limited: true` and `sampled_versions` (the number of dates obtained) in its
  resilience result. When the sample includes the oldest release,
  `avg_days_between_releases` is the span divided by the full release count.
  When the budget leaves no date at all, the module reports
  `data_available: false`, so it is reported as unavailable rather than
  measured from nothing.

On a fake proxy serving 5,000 versions for one module the old code made 5,001
requests (one list, 5,000 dates); the bounded code makes 25 (one list, 24
dates). docker/docker (26,422 versions) is the real case this prevents.

## Integrity

The Integrity scanner audits `go.mod` `replace` and `exclude` directives —
pure offline analysis, no network calls. Every `replace` directive is
classified by comparing the replacement module path against the original:

| Class                 | Condition                                                                                     | Severity | Grade effect                                    |
| --------------------- | ---------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------ |
| Version-pin           | Replacement path equals the original path                                                       | LOW      | None — expected, pins a specific version          |
| Local-path            | Replacement path is a filesystem path — relative, absolute, UNC, or drive-letter; both Unix and Windows syntaxes are recognized regardless of host OS | MEDIUM   | None (shown only)                                 |
| Major-version redirect | Replacement path is the original module gaining or swapping a `/vN` (N ≥ 2) semantic-import-versioning suffix (same underlying module) | MEDIUM   | None (shown only)                                 |
| Redirect              | Replacement path points to a genuinely different module                                         | HIGH     | None on the letter; shown in the integrity findings, and the `forbid_replace_redirect` policy rule fails on it |

Every `exclude` directive renders as an INFO finding for transparency. A
version-scoped replace (`replace A v1.2.3 => …`) only marks the dependency as
replaced when the selected version matches; the directive itself still appears
as a finding, annotated with the version it applies to. Replace directives are
integrity findings and policy inputs; they do not change the letter.

Enable the `forbid_replace_redirect` policy rule (on by default in the strict
preset) to fail CI when a redirect replace is present. The rule also fires on
test-only dependencies — test-time code still executes in CI (with access to CI
secrets), so a hijacked test-only dependency is not a safe blind spot for
policy purposes.

The rule does not look at `in_build`.
A `replace` directive is a `go.mod`-level statement about how the module graph
is resolved, and it applies whether or not any package of the replaced module
is currently imported; a redirect that is dormant today becomes live the
moment an import is added.

### go.sum verification

The Integrity scanner also audits `go.sum`:

| Finding            | Condition                                                                    | Severity | Grade effect                         |
| ------------------ | ---------------------------------------------------------------------------- | -------- | ------------------------------------ |
| `gosum_missing`    | `go.mod` declares requirements but no `go.sum` exists                        | HIGH     | None                                 |
| `gosum_incomplete` | A direct (non-replaced) dependency's resolved version has no `go.sum` entry  | MEDIUM   | None                                 |
| `gosum_mismatch`   | `go mod verify` reports a checksum mismatch (local module cache does not match `go.sum`) | CRITICAL | Whole-tree rule: the letter is F (`grade.checksum_mismatch`, `checksum_detail`) |

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
mismatch makes the letter F or fails the `require_gosum_verified` policy rule
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

| Condition                                     | Severity | Grade effect                    |
| ---------------------------------------------- | -------- | -------------------------------- |
| Confirmed test-only (`IsTestOnly == &true`)     | INFO     | None — surfaced for transparency  |
| Confirmed outside the build (`InBuild == &false`) | INFO   | None — surfaced for transparency  |
| Direct dependency, otherwise                    | MEDIUM   | None (shown only)                 |
| Transitive dependency, otherwise                | LOW      | None (shown only)                 |

An unknown classification (`IsTestOnly == nil` or `InBuild == nil`) is treated
as neither test-only nor outside the build, consistent with the scorer's
general convention of under-discounting rather than silently applying a
discount on unverified data.

Pseudo-version pins are findings and policy inputs only: they do not change the
letter. This is deliberate: routine pins such as `golang.org/x/telemetry` (which
has no tagged releases) are common in the Go ecosystem.

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
of it is imported by your code. Grading such a module as if it were compiled in
would let it decide the letter for a risk it cannot cause. After the graph is
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
production (this is what once put it at the top of the `spf13/cobra` result). The
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
  reachable from it in the module graph (`go mod graph`) **and listed in the
  main `go.mod`**, since the tagged build compiles that requirement's own
  dependencies. A module reachable from it but not listed in `go.mod` cannot be
  imported by the main module's tagged code (for go 1.17 and newer `go.mod`
  lists every module the build needs) and is classified from what is known:
  `in_build: false` when no list contains it. For a `go.mod` below go 1.17, which
  does not list every module, every reachable module stays unknown. The rule is "reachable
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
  and every module reachable from it in the module graph that `go.mod` lists are left unknown and
  counted as built. For a large tool such as a linter, that is its whole
  dependency tree, and those modules can then be graded. This errs
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
| Vulnerability score of a row | halved, capped at 50 | graph-only: shown, not graded | A finding in a module that is not compiled in cannot be exploited through the build |
| Upkeep score (archived, deprecated) | 10 | 10 | A module that is not compiled in cannot be an unpatchable risk to the build; see [grading.md](grading.md#upkeep-score) |
| Time bombs (archived, KEV, CRITICAL CVE) | skipped | skipped | Nothing that is not compiled in can detonate in the shipped code |
| Pseudo-version pin severity | INFO | INFO | See [Pseudo-version pins](#pseudo-version-pins) |
| `forbid_pseudo_versions` policy rule | exempt | exempt | Same reason |
| `no_unmaintained_months`, `no_archived`, `no_deprecated` policy rules | not exempt | exempt | The upkeep score and the time bombs already treat modules that are not compiled in separately; the gate agrees. An unknown `InBuild` is still checked |
| `forbid_replace_redirect` | not exempt | not exempt | A `replace` directive is a `go.mod`-level signal; see [Integrity](#integrity) |


## Response history

Response history says how fast a graded module adopted a dependency's fixes in
the past. It is shown as context next to a finding ("historically adopted
comparable fixes in about 30 days", with the sample size and period) and is
**never** part of the letter or the score. When there is not enough history the
report says so instead of showing a number.

For a module M and a dependency D, each earlier advisory of D that was fixed in
version F (released at `T_F`) gives one sample:

```
days = first sampled release of M whose go.mod requires D >= F   (its time)
       - T_F                                                     (never below 0)
```

- **Sampled releases** are M's newest `MaxVersions` (default 40) release
  versions without a pre-release, ordered by semver. A release that already
  required F before `T_F` counts 0 days.
- **F** is the lowest fixed version in the advisory's OSV `affected` ranges for
  D (ecosystem Go). Withdrawn advisories and advisories without a fix are
  skipped. Fixes sharing one version F are one sample, so an advisory listed
  under several identifiers is not counted twice.
- A fix released before M's oldest sampled release is skipped: M could not have
  reacted to it within the sample.
- The shown value is the integer median of the samples, rounded half up when
  the count is even, with the sample count and the span of the fixes' release
  times (`from`, `to`). It needs at least 3 samples (`MinResponseSamples`);
  otherwise the dependency is left out.
- **Bias:** a fix M never adopted in the sampled range is not a sample, because
  its adoption time is unknown. It is not counted as a long adoption, so the
  median leans towards faster adoption than the full record would show. Read it
  with the sample count.

The scan fails only when offline mode is on or M's own version list cannot be
read. Any other failed lookup (one go.mod, one release time, one dependency's
advisories) skips that item. Work is bounded in five ways, so a module with many
dependencies or advisories cannot hold the scan:

- `MaxVersions` (default 40) releases of M and `MaxDependencies` (default 60)
  dependencies;
- at most the newest 20 fixes of each dependency (fixes ascend by version);
- the release time of a fix is requested only when a sampled release of M
  adopted it; a fix nobody adopted is not a sample, so it costs no request;
- a request budget of `MaxRequests` (default 2000) for the whole call, proxy and
  OSV together: once spent, every further lookup counts as failed and is skipped;
- one overall `Deadline` (default 2 minutes) for the whole call, after which
  pending work is skipped.

A call with no dependencies makes no request. At most 8 requests run at once,
and a go.mod, release time or advisory list is requested once per scan. Nothing
is cached on disk.

### Endpoints

| Request | Purpose label (`--network-log`) | Host |
| ------- | ------------------------------- | ---- |
| `GET <proxy>/<M>/@v/list` | `responsehistory:version-list` | `proxy.golang.org` |
| `GET <proxy>/<M>/@v/<version>.info` (M's releases, and D at each fixed version) | `responsehistory:version-info` | `proxy.golang.org` |
| `GET <proxy>/<M>/@v/<version>.mod` | `responsehistory:go-mod` | `proxy.golang.org` |
| `POST /v1/query` with `{"package":{"name":D,"ecosystem":"Go"}}`, up to 5 pages | `responsehistory:osv` | `api.osv.dev` |

Only module paths and versions are sent. It is not available offline.

## Internal scorer (not published)

`pkg/scorer` still computes the pre-grading 0-100 risk score, per-dependency bands (LOW 0-25, MEDIUM 26-50, HIGH
51-75, CRITICAL 76-100) and a five-candidate project headline (`severity_adjusted`, `p95_dep_risk`, `archived_floor`,
`cve_floor`, `integrity_floor`). None of it is published in the text, JSON, PDF or SBOM output, and no policy gate reads
it: the letter is decided by `pkg/grade` from the scanners' signals (vulnerabilities with their reachability, upkeep
state, build membership, checksum verification). The scorer's formula is in `pkg/scorer/risk.go`, which is the only
authoritative description of it; its warnings that mention axis weights or comparability between scores are not
published either. The grade does not use the maintainer, resilience, maturity, depth or typosquat signals; those stay
on each dependency as data.
