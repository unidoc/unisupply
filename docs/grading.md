# Grading (rules version 2)

`unisupply` publishes one letter, A to F, and the evidence behind it. This page is the reference for how the letter is
decided. The code is `pkg/grade`; if this page and the code disagree, the code wins.

A grade is a statement about **known vulnerabilities and project upkeep** in the build that was scanned. **A** means
that nothing in this assessment crossed a scoring threshold. It does not say the project is secure, actively supported
or ready to release. The numbers below are policy values that pick a band. They are shown beside the letter (in each row, and in
`grade.score`) for traceability: they let you check the arithmetic behind a letter. They are not a measurement, not a
probability of compromise and not a risk score, and they carry no meaning outside the grade.

## One score per row

The module itself (the *self row*) and each dependency get one score:

```
row score = max(vulnerability score, upkeep score)
```

The letter comes from the **worst row**. The result always names that row (`grade.deciding`) and says why in one
sentence, with the arithmetic.

| Letter | Row score |
| ------ | --------- |
| A      | 0 to 10   |
| B      | 11 to 25  |
| C      | 26 to 50  |
| D      | 51 to 75  |
| F      | 76 to 100 |

D and F mean a confirmed problem: a known vulnerability in code that is reached, or a checksum that does not match.
Upkeep alone can reach C, never D or F.

### Vulnerability score

Reachability comes from govulncheck.

| Severity | Called (a path reaches the function) | Imported (package imported, function not reached) |
| -------- | ------------------------------------ | ------------------------------------------------- |
| Critical | 90                                   | 50 (cap)                                          |
| High     | 70                                   | 49                                                |
| Medium   | 45                                   | 32                                                |
| Low      | 15                                   | 11                                                |

- Imported code alone never scores above 50, so it cannot reach D.
- Each further distinct *called* high or critical advisory on the same row adds 5.
- A called finding on CISA's Known Exploited Vulnerabilities list scores at least 76 (F).
- A finding in a package that is never imported (*graph-only*) is shown and **not graded**. Its VEX status is
  `not_affected` / `vulnerable_code_not_present`.
- A row that is test-only (confirmed) halves the vulnerability score, capped at 50. A test-only known-exploited
  finding therefore lands at C. Unknown test-only status gets no discount.
- Reachability that was not determined is scored as *called*. The finding says so.
- A finding with no published severity is scored as medium. The letter is marked with `*` (for example `C*`) when that estimate could change it: the grade is computed again with every such severity as low and as critical, and a different letter in either run marks the result, whichever row the unknown severity is on. When rows tie, a row that does not rest on an estimate decides, so the text never depends on module names.
- A module that is confirmed not to be compiled in is graph-only whatever the reachability of its findings says.
- A row's vulnerability score is capped at 100.

### Upkeep score

Archived, deprecated (including a retracted version) rows score:

| Row                                 | Score |
| ----------------------------------- | ----- |
| The module itself                   | 35    |
| A dependency                        | 20    |
| Test-only, or not compiled in       | 10    |

A quiet project with nothing open scores 0. Being quiet is not a finding.

### Whole-tree rules

These only raise the letter:

- three or more *called* high or critical findings across the tree, any called critical, a called KEV finding, or a
  checksum mismatch (`go mod verify`): **F** (76);
- five or more called or imported high or critical findings: at least **D** (51).

Test-only dependencies are left out of the counts. A checksum mismatch applies in full everywhere. The rule that decided
is listed in `grade.tree_rows` and named in `grade.deciding`.

### Ties

When rows score the same, a vulnerability beats upkeep, then the module itself, then a direct dependency, then the module
path alphabetically. The result does not depend on input order.

## Private modules

A module matched by the private patterns is the customer's own code, and its name must not leave their boundary. The patterns are
Go's `GOPRIVATE` syntax (comma-separated globs, matched with `module.MatchPrefixPatterns`: `acme.example` matches
`acme.example/x` but not `acme.example.evil.com/x`). unisupply reads `GOPRIVATE` and `GONOPROXY` from the environment; the
option `runner.Options.PrivatePatterns` and the flag `--private-modules` (a comma list) replace them when set.

- **A private module path is in no request to any host and no facts-store call**: not the module proxy, not GitHub, not the Trust
  Index, not OSV by module, not the maintainer, activity, fix-date or response-history lookups, not `facts.Store` (neither `Get`
  nor `Put`). That includes the module itself when it is private. (The go command's own downloads follow `GOPRIVATE` by themselves.)
- **Private modules are not graded on upkeep.** Their row is `not_assessed` and marked `private` (`grade.rows[].private`, and
  `dependencies[].private` in the JSON), never missing: a private module does not make the grade Pending for "upkeep unread", and it is
  never counted as "not archived". A note says how many were not looked up.
- **Vulnerabilities for a private module are only what govulncheck finds from the public database**, which has none for a private
  path. A private module is therefore never graded as "checked and clean": the result says it was not looked up.

## Pending

A letter needs its checks. When a check that could change the letter did not run, the grade is **Pending**: there is no
letter, `grade.pending` says which check failed and why, and lists what is known.

1. the vulnerability scan failed or did not run;
2. the scan did not finish (timeout or interruption);
3. the module's own advisories could not be fetched, or its own status (archived, deprecated) could not be read and the
   worst it could be (35) would beat the worst row known;
4. a dependency's maintenance data is missing and could still beat the worst row;
5. `go mod verify` could not complete, so a checksum mismatch (F) cannot be ruled out;
6. the known-exploited status (CISA's catalog) could not be read for a reached finding with a CVE, and the letter is not
   already F: one on that list would grade F. When the catalog cannot be refreshed, a cached copy up to 30 days old is used and
   `grade.notes` states its date and age ("the copy from 2026-09-26 (14 days old)"); a copy older than 30 days is not a usable
   catalog, so the check counts as not run, as when there is no catalog at all;
7. `severity_lookup`: the severity of a reached finding could not be looked up (OSV, NVD and GitHub did not answer, usually
   NVD's rate limit without an API key) and a different severity would change the letter. A lookup that failed is a check that
   did not run, not an unpublished severity: it is retried (paced, with backoff) and, if it still fails, the grade is Pending.
   A severity nobody has published (the lookup answered) stays an estimate and marks the letter with `*`.

A Pending result publishes no letter, no deciding row and no score; `pending.known` says what is known.

**`pending.code` and `pending.kind`.** When the check is `vulnerability_scan` and the failure is a typed scan failure,
`pending` also has `code`, the failure's reason code (`multiple_mains`, `needs_newer_go`, `cgo_dependency`, `module_fetch`,
...), and `kind`, which says whether a retry can help: `transient` (network, timeout, rate limit), `permanent` (the
project cannot be scanned as it is) or `too_large` (a limit was exceeded). Both are absent for every other check, and for
a scan that failed with an error that is not a scan failure (the scan was skipped offline, for example). The codes are the
`scanner.Reason*` constants, listed in the CHANGELOG. A caller that decides on a retry reads `kind`, and `code` for what to
tell the user; `reason` is text for people, starts with the code (`the vulnerability scan did not run: multiple_mains:
b.go:3:6: main redeclared in this block`) and may change its wording.

```json
"pending": { "check": "vulnerability_scan", "code": "multiple_mains", "kind": "permanent", "reason": "the vulnerability scan did not run: multiple_mains: b.go:3:6: main redeclared in this block" }
```

A failure of `runner.Run` itself (no `go.mod`, an unreadable `go.mod`, an internal panic) is not a Pending grade: there is
no grade and no JSON report at all. The CLI prints the cause on stderr and exits 1; a Go caller gets the
`*scanner.ScanError` as the error of `runner.Run`, which is the only place its code and kind appear then.

**A scan that needs a newer Go than unisupply was built with.** govulncheck runs inside unisupply, compiled with one Go release. When
the Go the scan resolves for the project (its `go` directive or `toolchain` line) is a newer minor version, the scan stops before loading anything
and the grade is Pending (`vulnerability_scan`) with the reason "this unisupply was built with go1.26.9 and cannot scan code that
needs go1.27; rebuild unisupply with go1.27 or newer". Only a newer Go minor (language) version stops the scan. The same sentence replaces the loader's "file requires newer Go version"
error when that surfaces during a scan. A caller can check at startup with `scanner.CheckToolchain(scanGo)`.

**The standard library** is listed, not graded, by default (`--grade-stdlib` grades it as a row named `stdlib`): its advisories
follow the Go toolchain that runs the scan, which is not necessarily the one the project is built with, so the same project could
grade differently on another machine. The Go release it was matched against is always named in `grade.notes`, whether or not it
had findings. A module with no dependencies runs the vulnerability scan too, and lists its standard-library findings with the scan
block and the Go release note. They are not graded unless `--grade-stdlib` is set, and a scan that failed is then only a
warning (and no scan is claimed in the notes); under `--grade-stdlib` a failed scan is Pending (a letter must not come from a scan
that did not look), and so is a module with no Go package at all, which govulncheck cannot analyse. The note about the Go release
is written only when the scan ran.

**How long the fix existed before the scanned version was released.** With `--module-version`, the module proxy's release time of
that version is looked up (cached; a failed lookup only leaves the figure out). A finding whose fix was released more than a day
before that version says how long it had existed then: `response.fix_age_at_release_days` and the text "Fix available for 87 days
before this version was released (120 days to the scan date)". The field is absent when the release time is unknown, when the fix
came after the release, or when it came less than a day before. It is context: the letter never changes for it.

**A fix that needs a newer Go.** Many fixes only exist in versions that need a newer Go than the graded module supports: the x/*
modules raise their minimum to the previous Go release soon after each Go release (Go 1.27 on 18 August, and x/image v0.46.0 and
x/text v0.42.0 required Go 1.26 from 8 September), so a module that supports three Go releases cannot take a fix without dropping
the oldest. The grade does not change for that (the fix exists), but every finding with a fix says what it needs
(`response.fix_requires_go`, `response.fix_compat` = `raises_minimum` or `compatible`, and the text "The fix requires Go 1.26.0 or
newer; this module supports Go 1.24, so taking it raises the minimum Go version"), and `grade.notes` counts them
(`grade.fixes_need_newer_go`). The needed Go is the `go` directive of the fixed version's go.mod, read from the module proxy.

**Deprecation and retraction** are read from the go.mod of the module's LATEST version, as Go itself reports them (`go list -m -u`): a
dependency is deprecated when its latest go.mod says so (even if the pinned version predates the notice), and retracted when the
pinned version lies in a `retract` range of that go.mod. A module with no tagged release (the proxy has no `@latest`) is read at the
pinned version.

**Reachability that was not determined** is scored as called (the worst case): the finding says so
(`tier_assumed`, "Reachability not determined, scored as called"). Nothing is ever scored lower because the analysis could not tell.

**A dependency replaced by a local directory** (`replace example.com/lib => ../lib`) is the project's own code: there is no
published module to ask the proxy about, so its upkeep state is `not_assessed`, never "missing", and it does not make the grade
Pending; a project that has only such dependencies has no `go.sum`, and that is not read as a failed `go mod verify`.

**Archived flags need a GitHub token** for any project with more than a few GitHub-hosted modules: unauthenticated, GitHub allows
60 requests an hour. By default a grade is still given when the only gap is a dependency's archived flag: an archived dependency
adds at most 20 to its row (10 when test-only or not compiled in), so the letter may be one band better than it would be with the
flag. The row is graded on what is known. The module is listed in `grade.archived_unread`, and a note says so and says to set
`GITHUB_TOKEN`, only when the flag could change the letter: the row graded as archived must land in a worse band than the letter
(in practice an A that one archived dependency would make a B). On a C, D or F, or when the row already scores 20 or more, an unread
flag cannot change anything, and there is neither a list nor a note. A policy with `max_grade` treats a non-empty
`archived_unread` as not firm: it fails when the letter equals the maximum (`max_grade: "A"`), and otherwise passes with a
warning that names how many flags were unread and says to set `GITHUB_TOKEN`. With `--strict-archived`
(`StrictArchivedStatus`, used by services that publish letters) the same gap makes the grade Pending instead. The module's own
archived flag (a C) is always required.

A row nobody assessed (the module itself without a published version, a locally replaced dependency, the standard library) has the
upkeep state `not_assessed`, never `finished`.

A gate must treat a missing letter as "no result", never as a pass.

## The module itself

With `--module-version v1.2.3` the module is graded as that published version: its own OSV advisories are fetched and
assumed *called* (govulncheck does not check the module it starts from; whether a consumer imports the affected package
is theirs to know, and each advisory names the packages). Its archived and deprecated status is read the same way as a
dependency's. Without `--module-version` the module is not graded as a published module, and the result says so in
`grade.notes`. The version must be a full one (`v1.2.3`, `v1.2.3-rc.1`, optionally `+incompatible`); `v1` and `v1.2` are
rejected before anything is scanned, and OSV is asked for the version without `+incompatible`.

A dependency whose archived flag could not be read because its repository is not on GitHub, is unknown, or was not found
is not "not archived". It does not make the grade Pending (no retry could change it); one note in `grade.notes` names
how many such modules there are and the first three, sorted.

## Response window

A fix that was released recently still counts: current exposure is shown at once. Each finding carries a label such as
*"Fix released 8 October. Response window ends 22 October."* The window is 14 days from the fix release date (the later of
the advisory's fix date and the module proxy's time for the fixed version) and **never changes the letter**. A known
exploited finding has no window. With `--response-history`, a finding also says how fast the project adopted comparable
fixes in the past (the median over at least three fixes), as context and not a forecast.

## What is not published

The old 0 to 100 risk score as a weighted measurement (overall and per dependency), the five headline candidates, the AI-generation heuristic,
EPSS-adjusted scores and the takeover label are no longer published in any output. The 0 to 100 numbers that remain in
the grade rows are the policy values described at the top of this page, shown for traceability, not a score.
EPSS and KEV facts remain on each vulnerability as data.

For ONE release the JSON still carries `overall_risk_score`, `overall_risk_level`, `headline`, the `*_risk_count` summary fields and
the per-dependency `risk_score` / `risk_level`, derived from the grade (the score is the worst row's policy value, the level the
coarse band of the letter: A and B read LOW, C MEDIUM, D HIGH, F CRITICAL, UNKNOWN without a letter). On a Pending result the
deprecated scores (`overall_risk_score`, `headline.score`, and a dependency's `risk_score`, also when its row has no letter) are
left out, never 0: a v1 gate such as "overall_risk_score <= 60" must not pass a scan whose check did not run so consumers can move to the
`grade` object in steps. They are deprecated, listed in `deprecated_fields`, and removed in the next release.

The CI/CD audit (`--scan-ci`, `--scan-workflows`) is not part of the grade. It keeps its own 0 to 100 score, which is
reported in the CI/CD section of the output and is what the policy field `max_ci_score` gates on.

## When the called pass runs

govulncheck gives each finding a tier, and the tier is what the table above scores. It finds the tiers in two passes: the
imported pass (package level: is a package with an advisory imported?) is cheap, and the called pass (symbol level: does a
path reach the vulnerable function?) loads and analyses the whole call graph, which takes most of the time and gigabytes of
memory of a scan. unisupply runs the imported pass first and the called pass only when it can change the letter:
`grade.CalledPassCanChangeLetter` answers by scoring every imported finding as imported and as called, alone and under the
whole-tree rules, and asking whether the band differs. With the rules above that is true for any high or critical advisory, any
known-exploited one (called is at least F), and any with no severity yet; medium and low advisories land in the same band
either way. The standard library's advisories do not count unless `--grade-stdlib` grades them.

When the called pass is skipped, the findings are reported as imported, with no call path, and `scan.called_pass` is `skipped`
with `scan.called_pass_reason`. The imported pass does not type-check the packages (the called pass does), so a module whose packages do not compile is not a
failed scan when the called pass is skipped: nothing it imports could change the letter, and the grade is given from the imports. If
the called pass is needed and fails, the scan fails as before (`Pending`, with the typed reason). `--called-pass always` runs it on
every scan (the previous behaviour); `never` runs the imported
pass only, which can understate a letter and is for a quick listing, not for publishing one.

## JSON

The `grade` object of `--format json`:

```json
{
  "rule_version": 2,
  "letter": "F",
  "score": 80,
  "deciding": { "module": "golang.org/x/image", "reason": "called high GO-2026-0101 (70), +10 for 2 more called high or critical advisories", "score": 80 },
  "rows": [ { "module": "golang.org/x/image", "letter": "F", "vulnerability_score": 80, "upkeep_score": 0, "findings": [ ... ] } ],
  "tree_rows": [],
  "notes": []
}
```

Next to `grade`, the JSON has `scan_status` (`{"status": "complete" | "pending" | "interrupted" | "failed", "reason": ..., "kind": ..., "detail": ...}`: whether the result is final, and why not) and `dependency_graph` (`{"root": ..., "source": ..., "edges": [{"from": ..., "to": ...}]}`: which module requires which). A gate should read `scan_status.status` and treat everything but `complete` as no result.

`letter` is absent and `pending` present when the grade is Pending: `pending.check` names the check that did not run, and
for a failed `vulnerability_scan` `pending.code` and `pending.kind` carry the scan failure's reason code and kind (see
[Pending](#pending)). `estimated: true` marks a letter that an unpublished severity could change (`C*`).

## Policy

`max_grade` in a policy file is the worst letter allowed (`"C"` fails D and F). An enabled `max_grade` also fails when
no grade is available (grading was not run), and it fails on Pending unless `allow_pending` is `true`. With
`allow_pending`, a Pending grade passes the gate but is printed as a warning (`PASS (1 warning): ...`), so a gate that
passed on "no result" is never silent. A letter that was given without archived flags that could change it
(`grade.archived_unread` is not empty) is not a silent pass either: with `max_grade: "A"` it fails (the letter could be one band
worse), and with a looser maximum it passes with a warning naming the number of unread flags and saying to set `GITHUB_TOKEN`. The old `max_risk_score` and `max_overall_score` are gone, and a policy file that
still contains them is rejected. See [examples/policy-custom.md](../examples/policy-custom.md) for every policy field.

The exit code reflects the grade only when a policy is given (`--policy` or `--policy-preset`): without one, a grade of
F still exits 0. A scan that failed or was interrupted exits 4 after writing its report (`scan_status.status` `failed` or
`interrupted`, the typed reason in `scan_status.reason`); a policy violation (2) takes precedence.
