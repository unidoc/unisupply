# Annotated custom policy

`policy-custom.json` ships every supported policy field in one document so
you can copy it, delete the rules you do not need, and tune the thresholds
that remain. JSON forbids inline comments — this file is the per-field
reference.

The authoritative schema is the `Policy` struct in
[`pkg/policy/engine.go`](../pkg/policy/engine.go). If a field documented
here disagrees with that file, the source code wins.

## How matching works

- All numeric thresholds use `>` semantics: a violation fires when the
  measured value **exceeds** the threshold (e.g. `max_risk_score: 75`
  fails on score 76, not on 75).
- `allowed_modules` and `blocked_modules` match on **exact module path**
  or on **path prefix terminated by `/`**. Globs (`*`, `?`) are not
  supported and are treated as literal characters.
- `allowed_modules`, when set, applies to **direct dependencies only**.
  Transitive modules are never gated by the allowlist — gate them with
  `blocked_modules` or with risk-based fields if you need full-graph
  enforcement.
- `blocked_modules` applies to direct **and** transitive dependencies.

## Field reference

### Risk thresholds

#### `.max_risk_score` *(int, 0–100)*
Fails any single dependency whose composite risk score exceeds this
value. Use this to cap per-dependency risk regardless of project size.
**Strict preset:** `70`. **Moderate preset:** `85`.

#### `.max_overall_score` *(int, 0–100)*
Fails the project as a whole when the aggregated overall risk score
exceeds this value. Aggregation is risk-weighted, so a few high-risk
dependencies can pull the overall score up even when the median is
low. **Strict preset:** `50`. **Moderate preset:** `70`.

#### `.max_ci_score` *(int, 0–100)*
Gate on the CI/CD scanner's overall risk score (workflow pinning,
permissions, secret exposure). Only evaluated when `--scan-ci` is
enabled at the command line. **Strict preset:** `50`.

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
**Strict preset:** enabled. **Moderate preset:** enabled.

#### `.no_deprecated` *(bool)*
Fails any dependency whose `go.mod` carries a `// Deprecated:`
directive.

#### `.no_typosquatting` *(bool)*
Fails any dependency the typosquat scanner flags as similar to a
well-known module. **Strict preset:** enabled.

#### `.no_unmaintained_months` *(int)*
Fails any dependency whose last release is older than the given number
of months. **Strict preset:** `24`.

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

Exit code `0` means the policy parsed cleanly and no rules tripped;
exit code `2` means a rule fired (the scan succeeded, the policy
failed); any other non-zero exit is a tool error.
