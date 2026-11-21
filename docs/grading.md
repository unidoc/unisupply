# Grading (rules version 3, Grading v2.1)

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
There is one more way to a D, and it is a deliberate rules choice: a high or critical vulnerability in a package that is
imported, whose vulnerable function no call path reaches, scores C (49 or 50) until the fix for it has been available for 60 days. Then the
[overdue weight](#overdue-fixes) adds 5 and the row is a D (54 or 55). That finding's VEX status is still `not_affected` /
`vulnerable_code_not_in_execute_path`: the D says that a fix has waited two months, not that the function is reached.
Upkeep alone can reach C, never D or F.

### Vulnerability score

Reachability comes from govulncheck.

| Severity | Called (a path reaches the function) | Imported (package imported, function not reached) |
| -------- | ------------------------------------ | ------------------------------------------------- |
| Critical | 90                                   | 50 (cap)                                          |
| High     | 70                                   | 49                                                |
| Medium   | 45                                   | 32                                                |
| Low      | 15                                   | 11                                                |

- An imported finding scores at most 50 (the cap applies to the imported score). Only the [overdue weight](#overdue-fixes)
  can lift an imported row above it: an imported high whose fix is 60 days old or more is 49 + 5 = 54, a D.
- A row counts *per upgrade*. Among the called high or critical advisories of a row, all those that have a fix are **one
  problem** (one upgrade takes them all), and each advisory **without** a fix is a problem of its own. The worst
  advisory's score is taken, and each further problem adds 5. Three called highs in one module that one upgrade fixes
  are 70 (D); two without a fix, and a third with one, are 70 + 5 + 5 = 80 (F). Imported advisories add nothing for
  further problems.
- A finding whose fix is less than 14 days old is not counted: see [Grace for a fresh fix](#grace-for-a-fresh-fix).
- A row with a counted finding whose fix is 60 days old or more adds 5, once: see [Overdue fixes](#overdue-fixes).
- A called finding on CISA's Known Exploited Vulnerabilities list scores at least 76 (F).
- A finding in a package that is never imported (*graph-only*) is shown and **not graded**. Its VEX status is
  `not_affected` / `vulnerable_code_not_present`.
- A row that is test-only (confirmed) halves the vulnerability score, capped at 50. A test-only known-exploited
  finding therefore lands at C. Unknown test-only status gets no discount.
- Reachability that was not determined is scored as *called*. The finding says so.
- A finding with no published severity is scored as medium. The letter is marked with `*` (for example `C*`) when that estimate could change it: the grade is computed again with every such severity as low and as critical, and a different letter in either run marks the result, whichever row the unknown severity is on. When rows tie, a row that does not rest on an estimate decides, so the text never depends on module names.
- A module that is confirmed not to be compiled in is graph-only whatever the reachability of its findings says.
- A row's vulnerability score is capped at 100.

The order of operations on one row's vulnerability score:

1. the called findings: the worst one's table value, plus 5 for each further problem (above);
2. the imported findings: the worst one's table value, capped at 50;
3. the higher of the two;
4. plus 5 when a counted finding of the row has an overdue fix, then at most 100;
5. a called known-exploited finding: at least 76;
6. a confirmed test-only row: halved, at most 50.

A finding that is not counted (graph-only, or a fix under 14 days old) is in none of these steps.

### Overdue fixes

A row that has at least one *counted* finding (called or imported, not graph-only, not graced) whose fix has been available for
60 days or more (the scan time is on or after the fix release date plus 60 days) adds 5 to its vulnerability score, **once**,
however many such findings it has. It fires on any counted finding of the row, not only the one that sets the score: a row whose
worst finding is an imported high with a fix 23 days old, and which also has an imported medium whose fix is 181 days old, is
49 + 5 = 54. The +5 comes after the imported cap and before the known-exploited floor and the test-only halving. The row's
reason names the fix: `called high GO-2026-5032 (70); +5: fix for GO-2026-5032 available 174 days` (the finding that sets the score
when it is overdue itself, else the one whose fix is oldest). A finding with no fix, or whose fix date is unknown, is never overdue.

| Case | Arithmetic | Row |
| ---- | ---------- | --- |
| Three called highs in one module, one upgrade fixes them, the oldest fix 174 days old | 70 + 5 | 75, D |
| Two called highs with fixes 128 and 43 days old | 70 + 5 | 75, D |
| Two called highs, one has no fix, the other has a fix 100 days old | 70 + 5 (two problems) + 5 | 80, F |
| An imported high, fix 128 days old | 49 + 5 | 54, D |
| An imported high, fix 30 days old | 49 | 49, C |
| The same imported high, in a confirmed test-only row | (49 + 5) / 2 | 27, C |

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

- three or more *called* high or critical findings in **two or more modules**, any called critical, a called KEV finding, or a
  checksum mismatch (`go mod verify`): **F** (76). Three called highs in one module are that row's business: the row counts
  per upgrade (above);
- five or more called or imported high or critical findings, also in **two or more modules**: at least **D** (51).

Both count rules need two modules for the same reason: a row counts per upgrade, and the findings of one module are that row's
business. Five imported highs in one module that one upgrade fixes are the row's C 49 (a D once a fix has waited 60 days), not a D
by a tree rule that would count the same advisories again, one by one.

A finding whose fix is under 14 days old counts in no rule (a called critical with a fix 5 days old is not an F), and
neither does a graph-only one. Test-only dependencies are left out of the counts. A checksum mismatch applies in full everywhere. The rule that decided
is listed in `grade.tree_rows` and named in `grade.deciding`.

### Ties

When rows score the same, a vulnerability beats upkeep, then the module itself, then a direct dependency, then the module
path alphabetically. The result does not depend on input order.

## Private modules

A module matched by the private patterns is the customer's own code, and its name must not leave their boundary. The patterns are
Go's `GOPRIVATE` syntax (comma-separated globs, matched with `module.MatchPrefixPatterns`: `acme.example` matches
`acme.example/x` but not `acme.example.evil.com/x`). unisupply reads `GOPRIVATE` and `GONOPROXY` from the environment; the
option `runner.Options.PrivatePatterns` and the flag `--private-modules` (a comma list) replace them when set. The CLI also adds the `--private-modules` list to `GOPRIVATE` (and to
`GONOPROXY`/`GONOSUMDB` when the environment sets them) for the go command it starts, so it does not ask the module proxy or the
checksum database for those paths either. One exception: `GONOPROXY=none`, the setup `go help private` gives for a company
proxy that also serves the private modules, is left as it is, so those paths go to that proxy (`GOPROXY`) and not around it.
`GONOSUMDB=none` still gets the list: the go command reads `none` there as a pattern that matches no module, so leaving it would
send those paths to `GOSUMDB`. A library caller puts the same list in `GOPRIVATE` itself.

- **A private module path is in no request to any host and no facts-store call**: not the module proxy, not GitHub, not the Trust
  Index, not OSV by module, not the maintainer, activity, fix-date or response-history lookups, not `facts.Store` (neither `Get`
  nor `Put`). That includes the module itself when it is private. (The go command's own downloads follow `GOPRIVATE`; see above.)
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
3. `called_pass`: the analysis skipped govulncheck's called pass, and with the facts of the day (a known-exploited entry, a higher
   severity) it could now change the letter, so only a new analysis can say (see [A later grade](#a-later-grade));
4. the module's own advisories could not be fetched, or its own status (archived, deprecated) could not be read and the
   worst it could be (35) would beat the worst row known;
5. a dependency's maintenance data is missing and could still beat the worst row;
6. `go mod verify` could not complete, so a checksum mismatch (F) cannot be ruled out;
7. the known-exploited status (CISA's catalog) could not be read for a reached finding with a CVE, and the letter is not
   already F: one on that list would grade F. When the catalog cannot be refreshed, a cached copy up to 30 days old is used and
   `grade.notes` states its date and age ("the copy from 2026-09-26 (14 days old)"); a copy older than 30 days is not a usable
   catalog, so the check counts as not run, as when there is no catalog at all;
8. `severity_lookup`: the severity of a reached finding could not be looked up (OSV, NVD and GitHub did not answer, usually
   NVD's rate limit without an API key) and a different severity would change the letter. A lookup that failed is a check that
   did not run, not an unpublished severity: it is retried (paced, with backoff) and, if it still fails, the grade is Pending.
   A severity nobody has published (the lookup answered) stays an estimate and marks the letter with `*`.

A Pending result publishes no letter, no deciding row and no score; `pending.known` says what is known.

**`pending.code` and `pending.kind`.** When the check is `vulnerability_scan` and the failure is a typed scan failure,
`pending` also has `code`, the failure's reason code (`multiple_mains`, `needs_newer_go`, `cgo_dependency`,
`module_fetch`, ...), and `kind`, which says whether a retry can help: `transient` (network, timeout, rate limit, or the
scan's child process killed with SIGKILL, as the out-of-memory killer does, or out of memory: a later retry, or one with
more memory or fewer scans at once, can help), `permanent` (the project cannot be scanned as it is) or `too_large` (a
limit was exceeded). Both are absent for every other check, and for a scan that failed with an error that is not a scan
failure (the scan was skipped offline, for example). The codes are the `scanner.Reason*` constants, listed in the
CHANGELOG. A caller that decides on a retry reads `kind`, and `code` for what to tell the user; `reason` is text for
people, starts with the code (`the vulnerability scan did not run: multiple_mains: b.go:3:6: main redeclared in this
block`) and may change its wording.

```json
"pending": { "check": "vulnerability_scan", "code": "multiple_mains", "kind": "permanent", "reason": "the vulnerability scan did not run: multiple_mains: b.go:3:6: main redeclared in this block" }
```

A failure of `runner.Run` itself (no `go.mod`, an unreadable `go.mod`, an internal panic) is not a Pending grade: there is
no grade and no JSON report at all. The CLI prints the cause on stderr and exits 1; a Go caller gets the
`*scanner.ScanError` as the error of `runner.Run`, which is the only place its code and kind appear then.

**A scan that needs a newer Go than unisupply was built with.** govulncheck runs inside unisupply, compiled with one Go release. When
the Go the scan resolves for the project (its `go` directive or `toolchain` line) is a newer minor version, the scan stops before loading anything
and the grade is Pending (`vulnerability_scan`) with the reason "this unisupply was built with go1.N.x and cannot scan code that
needs go1.M; rebuild unisupply with go1.M or newer" (the Go unisupply was built with and the project's Go minor version). Only a newer Go minor (language) version stops the scan. The same sentence replaces the loader's "file requires newer Go version"
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

## Grace for a fresh fix

A finding whose fix was released less than 14 days ago **does not count toward the letter**. It is excluded from its row's
score, from the [overdue check](#overdue-fixes) and from every whole-tree rule. It is still listed: `counted` is `false`,
`vex` and `tier` are unchanged, `response.status` is `within_window`, and the finding's `note` gives the day it starts to
count ("Fix is 8 days old: it counts toward the letter from 16 October."). The result has one note in `grade.notes` that says how many
findings are in the window and the earliest day one starts to count. A row whose only findings are in the window reads
"findings with a fix under 14 days old are shown, not graded yet". Each finding also carries a label such as
*"Fix released 8 October · response window ends 22 October."*

- The window runs from the fix release date (the later of the advisory's fix date and the module proxy's time for the fixed
  version). A finding counts from exactly 14 days after that moment: 13 days 16 hours after it is graced, 14 days after it is not.
- A known-exploited finding (CISA KEV) gets no grace: it counts on the day the fix is out.
- A finding whose known-exploited status could not be checked gets no grace either: it has a CVE and CISA's catalog could not be
  read, so it might be on the list, and it counts (the safe direction). Its note says so ("Its known-exploited status could not be
  checked, so it counts without the grace period.") and its response label says it counts at once. A Go advisory without a CVE cannot be
  on the list and keeps the grace. A called finding in this state also makes the grade Pending (`known_exploited`, see [Pending](#pending)).
- A finding with no fix has nothing to wait for, and one whose fix date is unknown counts, with no grace. Neither is ever overdue.
- A finding in a package that is not imported (graph-only) is not counted anyway and has no grace note.
- A fix that is under 14 days old is never "overdue": the two states do not overlap.

The grace delays the effect of a new fix on the letter. It does not remove it. A scan run a few hours after the fix turns 14 days old
can grade a band or more worse than one run a few hours before, with no change to the advisory or the project; the same holds at
60 days, when the overdue weight starts. A caller that grades a stored analysis again should do it on a date, not only when an
advisory changes.

With `--response-history`, a finding also says how fast the project adopted comparable fixes in the past (the median over at least
three fixes), as context and not a forecast.

## What would change the letter

When the letter has a deciding row (or a whole-tree rule) and an upgrade would change it, `grade.next_step` names the one that would
improve it most. It is given for any letter with a deciding row, not only for a D or F: a C that rests on an imported medium gets one too.

```json
"next_step": {
  "module": "golang.org/x/image",
  "version": "v0.43.0",
  "command": "go get golang.org/x/image@v0.43.0",
  "clears": ["GO-2026-5032", "GO-2026-5062", "GO-2026-5066"],
  "letter_after": "A",
  "score_after": 0
}
```

(In Go: `grade.NextStep`, `grade.Result.NextStep`.) The text and PDF reports show it as one line next to "Decided by": `Next step: go get
golang.org/x/image@v0.43.0 (clears 3 advisories; the letter would be A)`.

- **The target** is the highest fixed version, compared as a semantic version (`v0.10.0` is above `v0.9.0`), among the row's *counted*
  and *graced* findings that have a fix. A fix still in the grace window sets the target because it counts in a few days: an
  upgrade that skipped it would be undone by it. A graph-only finding does not set the target. A fixed version that is not a
  version is skipped. The row is a candidate only if it has at least one counted finding with a fix.
- **`clears`** lists, sorted, every advisory of that row that the target fixes (every one whose fixed version is at or below it), in
  any tier. It includes graph-only advisories and advisories in the grace window that the upgrade also fixes.
- **`letter_after` and `score_after`** come from grading again, the full decision, with those advisories removed from the row, so they
  are honest: when another row is nearly as bad the letter after is D, not A. If the grade after the upgrade would be Pending (a
  check that the letter would then depend on did not run, a severity lookup that failed, say), `letter_after` and `score_after` are
  absent and `pending_after` names the check that would not have run. With a letter, `score_after` is always there, 0 included.
- **Which row.** When a row decides by its vulnerability score, it is that row's upgrade, named only when it changes something:
  that row's own score after is lower, or the grade after would be Pending. (A deciding high with no fix, next to a medium that has
  one, gets no step: upgrading the medium leaves the row's score as it is. A D that stays a D with a lower score, as another row
  takes over, is named, and so is one that stays D 70 because another row ties with it: the upgrade is the first of the two
  needed.) When a whole-tree rule decides, every row
  with a counted finding that has a fix is graded again and the best result is taken: one that is not Pending, then the better letter,
  then the lower score, then the row that comes first in `grade.rows`. A whole-tree rule names a step **only if it improves the
  letter**: there is none for a checksum mismatch, which no upgrade clears.
- **There is no `next_step`** when the grade is Pending, when nothing decides it (an A), when upkeep decides the row (an archived
  dependency), when the deciding row has no counted finding with a fix, or when the upgrade would change nothing.
- **The module itself** gets the same `go get` command (a consumer moves to the fixed release). **The standard library** (graded
  with `--grade-stdlib`) gets the toolchain form: `go get toolchain@go1.24.4`, with `version` `v1.24.4`. A fixed version is read as `go1.26.9`, `v1.26.9`,
  `1.26.9`, `1.21` (the release Go calls go1.21.0) or a release candidate or beta (`go1.22rc1`, which compares below the release,
  and is `version` `v1.22.0-rc.1`); the command uses the Go spelling of the chosen version, never the semver form.

The step is a statement about the letter, not a promise about the build: the fixed version may need a newer Go than the module
supports (see [Pending](#pending), "A fix that needs a newer Go").

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
either way (imported 32 and called 45 are both C, and with the overdue 5 added, 37 and 50 still are; halved for a test-only row,
18 and 25 are both B). The findings it builds have no fix date, so neither the grace nor the overdue weight is applied to them. That
is the safe side: a date can only move a medium or low finding within its band, and a high or critical finding is a "yes" already.
An answer of yes costs a scan, never a wrong letter. The standard library's advisories do not count unless `--grade-stdlib` grades them.

When the called pass is skipped, the findings are reported as imported, with no call path, and `scan.called_pass` is `skipped`
with `scan.called_pass_reason`. Each finding says the same on its own in `call_path_checked` (in `dependencies[].vulnerabilities[]`,
`stdlib_vulnerabilities[]`, `grade.rows[].findings[]` and the stored analysis), for a reader that keeps findings without the scan
header: `true` when the called pass covered it, so its tier is govulncheck's verdict on the call path (an `imported` finding was
checked and is not called), `false` when the called pass was skipped (an `imported` finding may be called) or the finding did
not come from govulncheck (the module's own advisories). It is context only: the score does not read it. An analysis stored by
v0.9.0, before findings carried it, is graded with every finding checked when its `scan.called_pass` is `ran`. The imported pass does not type-check the packages (the called pass does), so a module whose packages do not compile is not a
failed scan when the called pass is skipped: nothing it imports could change the letter, and the grade is given from the imports. If
the called pass is needed and fails, the scan fails as before (`Pending`, with the typed reason). `--called-pass always` runs it on
every scan (the previous behaviour); `never` runs the imported
pass only, which can understate a letter and is for a quick listing, not for publishing one. A grade made from a `never` scan
has a note that says its letter is a floor.

### A later grade

The decision to skip the called pass is made from the severities and known-exploited status of the day of the analysis.
`runner.Grade` grades a stored analysis again with the facts of a later day, and a fact can change since: an advisory is added to
CISA's catalog, or NVD re-rates it. The advisory fingerprint in the analysis's identity hashes the vulnerability database's index
(ID, modified, fixed) and does not see either. So `Grade` asks the same question again with the facts of the day: when the
analysis skipped the called pass in `auto` mode and the answer is now yes, the grade is **Pending** on `called_pass`, with no letter,
and the reason says to analyse again. The imported finding would otherwise keep a letter that a called one would not get (the
known-exploited F floor and the called critical score apply to called findings only). The same holds for an analysis made without
`--grade-stdlib` and graded with it.

## JSON

The `grade` object of `--format json`:

```json
{
  "rule_version": 3,
  "letter": "D",
  "score": 75,
  "deciding": { "module": "golang.org/x/image", "reason": "called high GO-2026-5032 (70); +5: fix for GO-2026-5032 available 174 days", "score": 75 },
  "next_step": { "module": "golang.org/x/image", "version": "v0.43.0", "command": "go get golang.org/x/image@v0.43.0", "clears": ["GO-2026-5032", "GO-2026-5062", "GO-2026-5066"], "letter_after": "A", "score_after": 0 },
  "rows": [ { "module": "golang.org/x/image", "letter": "D", "vulnerability_score": 75, "upkeep_score": 0, "findings": [ ... ] } ],
  "tree_rows": [],
  "notes": []
}
```

Next to `grade`, the JSON has `scan_status` (`{"status": "complete" | "pending" | "interrupted" | "failed", "reason": ..., "kind": ..., "detail": ...}`: whether the result is final, and why not) and `dependency_graph` (`{"root": ..., "source": ..., "edges": [{"from": ..., "to": ...}]}`: which module requires which). A gate should read `scan_status.status` and treat everything but `complete` as no result.

`rule_version` is 3. A result is never re-labelled: a grade made under another version was made under that version's rules, and a stored
analysis graded again today gets today's. `counted` on a finding is `false` for a graph-only finding and, since rules version 3, for a
finding whose fix is under 14 days old. The grade of a stored analysis can change from one day to the next with no advisory change
(day 14 and day 60 after a fix), so a service that re-grades should do it on a date.

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
