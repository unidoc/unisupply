# Annotated custom policy

`policy-custom.json` ships every supported policy field in one document so
you can copy it, delete the rules you do not need, and tune the thresholds
that remain. JSON forbids inline comments — this file is the per-field
reference.

The authoritative schema is the `Policy` struct in
[`pkg/policy/engine.go`](../pkg/policy/engine.go). If a field documented
here disagrees with that file, the source code wins.

## How matching works

- Numeric thresholds use `>` semantics: a violation fires when the
  measured value **exceeds** the threshold (e.g. `max_ci_score: 50`
  fails on a CI/CD score of 51, not on 50).
- `max_grade` compares letters: it fails any grade **worse** than the
  given one (`"C"` fails D and F, passes C and better).
- A policy file is decoded strictly: an unknown key is rejected at load
  time (exit 1). The removed `max_risk_score` and `max_overall_score`
  are unknown keys.
- `allowed_modules` and `blocked_modules` match on **exact module path**
  or on **path prefix terminated by `/`**. Globs (`*`, `?`) are not
  supported and are treated as literal characters.
- `allowed_modules`, when set, applies to **direct dependencies only**.
  Transitive modules are never gated by the allowlist — gate them with
  `blocked_modules` or with `max_grade` if you need full-graph
  enforcement.
- `blocked_modules` applies to direct **and** transitive dependencies.

## Field reference

### Grade and CI/CD thresholds

#### `.max_grade` *(string, `"A"` to `"F"`)*
The worst letter the project may have. `"C"` fails a D or an F;
`"A"` fails everything but an A. The violation names the row that decided
the letter. A letter marked estimated (`C*`) is checked as its letter.
When `max_grade` is enabled it also **fails when there is no grade**:
grading did not run, or the grade is Pending (a check the grade needs
did not run, so there is no letter). A gate must not pass on "no result".
A letter given without some archived flags that could change it
(`grade.archived_unread` is not empty: no `GITHUB_TOKEN`) is not a firm pass: it
fails with `"A"`, and with a looser maximum it passes with a warning that names
how many flags were unread and says to set `GITHUB_TOKEN`.
**Strict preset:** `"B"`. **Moderate preset:** `"C"`.

#### `.allow_pending` *(bool)*
Lets a Pending grade pass `max_grade`. The Pending result is then
reported as a warning, not an error: the run passes and the text output
reads `PASS (1 warning): ...` followed by the warning line. Without
`allow_pending` (the default), Pending fails the gate with exit code `2`.
Use it for a gate that must not break on a network or vulnerability
database outage, and keep a second check (for example a scheduled report)
that looks at Pending. It has no effect without `max_grade`.

#### `.max_ci_score` *(int, 0–100)*
Gate on the CI/CD scanner's overall score (workflow pinning,
permissions, secret exposure). The CI/CD audit is not part of the grade
and keeps its own 0–100 score. Only evaluated when `--scan-ci` or
`--scan-workflows` is enabled at the command line. **Strict preset:** `50`.

### Vulnerability rules

#### `.no_known_vulns` *(bool)*
Fails on any dependency with a known CVE, regardless of severity.
This is the strictest possible vulnerability rule — even informational
findings will fail the build. Most teams should use
`no_critical_vulns` instead.

#### `.no_critical_vulns` *(bool)*
Fails only on `CRITICAL` or `HIGH` severity vulnerabilities. This is
the rule both built-in presets enable. Pair with
`no_unmaintained_months` to also catch silently-unmaintained packages
that have not yet had a CVE filed.

### Maintainer / lifecycle rules

#### `.no_single_maintainer` *(bool)*
Fails any **direct** dependency whose GitHub bus factor is `≤ 1`. The
rule deliberately ignores transitive dependencies because the bus
factor signal is noisy at depth and rarely actionable. **Strict
preset:** enabled.

#### `.no_archived` *(bool)*
Fails any dependency whose repository is marked archived on GitHub.
Dependencies confirmed to be outside the build (`in_build: false`, in the
module graph only) are exempt; a dependency whose build membership is
unknown is not. **Strict preset:** enabled. **Moderate preset:** enabled.

#### `.no_deprecated` *(bool)*
Fails any dependency whose latest version's `go.mod` carries a
`// Deprecated:` notice on its `module` directive, or that the module
proxy reports as gone. The violation includes the deprecation message,
which usually names the successor. Dependencies confirmed to be outside the
build (`in_build: false`) are exempt; a dependency whose build membership is
unknown is not. Neither preset enables this rule.

#### `.no_typosquatting` *(bool)*
Fails any dependency the typosquat scanner flags as similar to a
well-known module. **Strict preset:** enabled.

#### `.no_unmaintained_months` *(int)*
Fails any dependency that has had neither a release nor a commit on its
repository's default branch within the given number of months. Without
default-branch data (offline, no branch found, lookup failed) the
release age alone decides. Dependencies confirmed to be outside the build
(`in_build: false`) are exempt; a dependency whose build membership is
unknown is not. **Strict preset:** `24`.

### Dependency graph rules

#### `.max_depth` *(int)*
Fails any dependency whose transitive depth from the root module
exceeds this value. Direct dependencies are at depth `1`. Use this to
flag deeply-nested transitive chains where a compromise is harder to
notice. Neither preset enables this rule.

### Integrity rules

#### `.forbid_replace_redirect` *(bool)*
Fails any `go.mod` `replace` directive that redirects a module to a
different module path (a fork or private mirror). Version-pin and
local-path replaces are not affected. Fires even for test-only modules,
because test code runs in CI. **Strict preset:** enabled.

#### `.require_gosum_verified` *(bool)*
Fails when `go mod verify` reported a checksum mismatch. Outcomes that
mean "not verified" (offline, no go.sum, toolchain unavailable) do not
fail: the rule rejects confirmed tampering, not missing data.
**Strict preset:** enabled.

#### `.forbid_pseudo_versions` *(bool)*
Fails any dependency pinned to a pseudo-version, except modules
confirmed test-only or outside the build. **Strict preset:** enabled.

### Allow / deny lists

#### `.allowed_modules` *(string[])*
When non-empty, every **direct** dependency must match either an exact
module path entry or be under a path prefix entry terminated by `/`.
Transitive modules are not evaluated against this list.

```json
"allowed_modules": [
  "golang.org/x/",            // matches all golang.org/x/* modules
  "github.com/unidoc/",       // matches all github.com/unidoc/* modules
  "github.com/spf13/pflag"    // matches that exact module only
]
```

A trailing `/` on a prefix entry is optional — `golang.org/x/` and
`golang.org/x` both match `golang.org/x/<anything>`.

#### `.blocked_modules` *(string[])*
Always-fail list, applied to direct and transitive dependencies.
Same exact-or-prefix matching as `allowed_modules`.

```json
"blocked_modules": [
  "github.com/suspicious/pkg",
  "github.com/known-bad/"
]
```

## Validation

The CLI does not yet ship a standalone `--policy-validate` flag. To
sanity-check a policy file, run a scan against any Go module — the
policy is parsed before any scanner work and reports any structural
problems immediately:

```bash
unisupply ./ --policy ./examples/policy-custom.json
```

Exit code `0` means the policy parsed cleanly and no rules tripped
(warnings, such as a Pending grade allowed by `allow_pending`, do not
change the exit code and are printed); exit code `2` means a rule fired
(the scan succeeded, the policy failed); any other non-zero exit is a
tool error. Without `--policy` or `--policy-preset` the exit code ignores
the grade: a grade of F still exits `0`.

## Field table

| Field | Type | Default | Strict | Moderate |
| ----- | ---- | ------- | ------ | -------- |
| `max_grade` | `"A"`–`"F"` | off | `"B"` | `"C"` |
| `allow_pending` | bool | `false` | off | off |
| `max_ci_score` | int | off | `50` | off |
| `no_known_vulns` | bool | off | off | off |
| `no_critical_vulns` | bool | off | on | on |
| `no_single_maintainer` | bool | off | on | off |
| `no_archived` | bool | off | on | on |
| `no_deprecated` | bool | off | off | off |
| `no_typosquatting` | bool | off | on | off |
| `no_unmaintained_months` | int | off | `24` | off |
| `max_depth` | int | off | off | off |
| `forbid_replace_redirect` | bool | off | on | off |
| `require_gosum_verified` | bool | off | on | off |
| `forbid_pseudo_versions` | bool | off | on | off |
| `allowed_modules` | string[] | off | off | off |
| `blocked_modules` | string[] | off | off | off |
