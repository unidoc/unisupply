# Grading (rules version 2)

`unisupply` publishes one letter, A to F, and the evidence behind it. This page is the reference for how the letter is
decided. The code is `pkg/grade`; if this page and the code disagree, the code wins.

A grade is a statement about **known vulnerabilities and project upkeep** in the build that was scanned. **A** means
that nothing in this assessment crossed a scoring threshold. It does not say the project is secure, actively supported
or ready to release. The numbers below are policy values that pick a band. They are not probabilities of compromise and
are not published as a score.

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
- A finding with no published severity is scored as medium, and the letter it decides is marked `C*`.

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

## Pending

A letter needs its checks. When a check that could change the letter did not run, the grade is **Pending**: there is no
letter, `grade.pending` says which check failed and why, and lists what is known.

1. the vulnerability scan failed or did not run;
2. the scan did not finish (timeout or interruption);
3. the module's own archived/deprecated status could not be read, or its own advisories could not be fetched;
4. a dependency's maintenance data is missing and could still beat the worst row.

A gate must treat a missing letter as "no result", never as a pass.

## The module itself

With `--module-version v1.2.3` the module is graded as that published version: its own OSV advisories are fetched and
assumed *called* (govulncheck does not check the module it starts from; whether a consumer imports the affected package
is theirs to know, and each advisory names the packages). Its archived and deprecated status is read the same way as a
dependency's. Without `--module-version` the module is not graded as a published module, and the result says so in
`grade.notes`.

## Response window

A fix that was released recently still counts: current exposure is shown at once. Each finding carries a label such as
*"Fix released 8 October. Response window ends 22 October."* The window is 14 days from the fix release date (the later of
the advisory's fix date and the module proxy's time for the fixed version) and **never changes the letter**. A known
exploited finding has no window. With `--response-history`, a finding also says how fast the project adopted comparable
fixes in the past (the median over at least three fixes), as context and not a forecast.

## What is not published

The 0 to 100 score, the five headline candidates, the AI-generation heuristic, EPSS-adjusted scores and the takeover
label are no longer published in any output. EPSS and KEV facts remain on each vulnerability as data.

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

`letter` is absent and `pending` present when the grade is Pending. `estimated: true` marks a `C*`.

## Policy

`max_grade` in a policy file is the worst letter allowed (`"C"` fails D and F). Pending fails unless `allow_pending` is
set. The old `max_risk_score` and `max_overall_score` are gone, and a policy file that still contains them is rejected.
