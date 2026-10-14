#!/usr/bin/env bash
#
# Render a unisupply JSON report as markdown, for both the workflow job
# summary and the weekly security issue body.
#
# One renderer for both consumers, on purpose: a letter is not a report, so both
# carry the same deciding row, time bombs and per-dependency grade rows, and
# neither can drift away from the other.
#
# The grade is read from .grade (Grading v2): .grade.letter, .grade.pending,
# .grade.deciding and .grade.rows[]. The 0-100 numbers in the rows are policy
# values shown for traceability; they are not a risk score.
#
# Usage:
#   render-scan-report.sh <unisupply.json> [stale-deps.txt] [stale-90.txt]
#
# Environment (all optional):
#   GOVULNCHECK_RC  govulncheck exit code (3 = reachable vulnerability found)
#   STALE           "true" when dependencies older than 90 days were found
#   AUDIT_RESULT    result of the audit job, when the caller knows it
#   MAX_DEPS        rows in the grade-row table (default 10)
#   MAX_VULNS       rows in the vulnerability table (default 15)
#   MAX_WARNINGS    warnings listed before collapsing to a count (default 15)
#
# Writes markdown to stdout. Scan-derived strings (module paths, advisory
# summaries, warnings) are extracted with `jq -r` and never interpolated into
# a jq program, and are rendered inside code spans or table cells so a crafted
# module path cannot restructure the document.

# jq programs are single-quoted on purpose: shell expansion inside one would
# be an injection vector, so values reach jq through --argjson instead.
# shellcheck disable=SC2016

set -euo pipefail

JSON="${1:-}"
STALE_DEPS="${2:-}"
STALE_90="${3:-}"

MAX_DEPS="${MAX_DEPS:-10}"
MAX_VULNS="${MAX_VULNS:-15}"
MAX_WARNINGS="${MAX_WARNINGS:-15}"

if [ -z "$JSON" ]; then
  echo "usage: $(basename "$0") <unisupply.json> [stale-deps.txt] [stale-90.txt]" >&2
  exit 64
fi

# jq_field runs a jq program against the report and prints its output. Kept as
# a function so every read goes through the same "-r, never interpolate"
# discipline.
jq_field() {
  jq -r "$1" "$JSON"
}

# --- Fallback: no scan output ------------------------------------------------
#
# A missing or empty report is itself the finding. Say so and stop, rather
# than emitting a document of "(none)" rows that reads like a clean scan.

if [ ! -s "$JSON" ]; then
  echo "# Supply Chain Self-Scan"
  echo
  echo "> ⚠️ **No scan output.** \`$(basename "$JSON")\` is missing or empty, so"
  echo "> nothing below could be measured. This is not a clean result — it is"
  echo "> an absent one."
  if [ -n "${AUDIT_RESULT:-}" ] && [ "${AUDIT_RESULT}" != "success" ]; then
    echo ">"
    echo "> The audit job result was \`${AUDIT_RESULT}\`."
  fi
  exit 0
fi

if ! jq -e . "$JSON" >/dev/null 2>&1; then
  echo "# Supply Chain Self-Scan"
  echo
  echo "> ⚠️ **Unreadable scan output.** \`$(basename "$JSON")\` is not valid JSON."
  exit 0
fi

# --- Grade -------------------------------------------------------------------
#
# GRADE_STATE: "graded" (a letter), "pending" (a check the grade needs did not
# run: there is no letter, and it is not a pass) or "none" (no .grade at all:
# grading was not run). A missing letter is never read as good.

GRADE_STATE=$(jq_field '
  if .grade == null then "none"
  elif .grade.pending != null or (.grade.letter // "") == "" then "pending"
  else "graded" end
')
LETTER=$(jq_field '.grade.letter // ""')
ESTIMATED=$(jq_field '.grade.estimated // false')

case "$GRADE_STATE" in
  graded)
    LABEL="$LETTER"
    if [ "$ESTIMATED" = "true" ]; then
      LABEL="${LABEL}*"
    fi
    case "$LETTER" in
      A|B) GRADE_BADGE="🟢 ${LABEL}" ;;
      C)   GRADE_BADGE="🟡 ${LABEL}" ;;
      D)   GRADE_BADGE="🟠 ${LABEL}" ;;
      F)   GRADE_BADGE="🔴 ${LABEL}" ;;
      *)   GRADE_BADGE="⚪ ${LABEL}" ;;
    esac
    ;;
  pending) LABEL="PENDING"; GRADE_BADGE="⚪ PENDING (no letter)" ;;
  *)       LABEL="NO GRADE"; GRADE_BADGE="⚪ no grade (grading was not run)" ;;
esac

case "${GOVULNCHECK_RC:-}" in
  0)  GOVULN_BADGE="🟢 0 — no vulnerabilities" ;;
  3)  GOVULN_BADGE="🔴 3 — call-graph-reachable vulnerability found" ;;
  "") GOVULN_BADGE="⚪ (not run)" ;;
  *)  GOVULN_BADGE="🟠 ${GOVULNCHECK_RC} — tool error" ;;
esac

echo "## Grade"
echo
echo "| Field | Value |"
echo "|---|---|"
echo "| Supply-chain grade | **${GRADE_BADGE}** |"
echo "| govulncheck exit code | ${GOVULN_BADGE} |"
echo "| Stale dependencies (>90d) | ${STALE:-unknown} |"

GENERATED=$(jq_field '.generated_at // ""')
if [ -n "$GENERATED" ]; then
  echo "| Scan generated at | ${GENERATED} |"
fi

GOSUM=$(jq_field '.module_directives.gosum_verified // ""')
if [ -n "$GOSUM" ]; then
  case "$GOSUM" in
    true)  GOSUM_BADGE="🟢 verified (\`go mod verify\`)" ;;
    false) GOSUM_BADGE="🔴 MISMATCH — module cache does not match go.sum" ;;
    *)     GOSUM_BADGE="⚪ ${GOSUM}" ;;
  esac
  echo "| go.sum verification | ${GOSUM_BADGE} |"
fi
echo

# What decided the letter, or why there is none. Without it the letter looks
# arbitrary; with a Pending grade it says which check did not run.
if [ "$GRADE_STATE" = "pending" ]; then
  PENDING_CHECK=$(jq_field '.grade.pending.check // ""')
  PENDING_REASON=$(jq_field '.grade.pending.reason // ""')
  LINE="> **PENDING** — no letter"
  if [ -n "$PENDING_CHECK" ]; then
    LINE="${LINE}: check \`${PENDING_CHECK}\` did not run"
  fi
  if [ -n "$PENDING_REASON" ]; then
    LINE="${LINE} — ${PENDING_REASON}"
  fi
  echo "$LINE"
  echo
  if [ "$(jq_field '(.grade.pending.known // []) | length')" -gt 0 ]; then
    echo "> What is known anyway:"
    jq_field '(.grade.pending.known // [])[] | "> - \(.)"'
    echo
  fi
elif [ "$GRADE_STATE" = "graded" ]; then
  DECIDING=$(jq_field '
    (.grade.deciding // null) as $d
    | if $d == null then ""
      elif ($d.tree_rule // "") != "" then "whole-tree rule \($d.tree_rule)"
      elif $d.self == true then "this module"
      else "\($d.module // "")" end
  ')
  DECIDING_REASON=$(jq_field '.grade.deciding.reason // ""')
  if [ -n "$DECIDING" ]; then
    LINE="> **${LABEL}** decided by \`${DECIDING}\`"
    if [ -n "$DECIDING_REASON" ]; then
      LINE="${LINE} — ${DECIDING_REASON}"
    fi
    echo "$LINE"
    echo
  fi
fi

CHECKSUM_DETAIL=$(jq_field 'if .grade.checksum_mismatch == true then (.grade.checksum_detail // "checksum mismatch") else "" end')
if [ -n "$CHECKSUM_DETAIL" ]; then
  echo "> 🔴 **Checksum mismatch** — ${CHECKSUM_DETAIL}"
  echo
fi

# --- Time bombs --------------------------------------------------------------
#
# Never inside <details>. These exist to be undeniable. The scope note mirrors
# timeBombScopeNote in pkg/report/text.go (used by the text and PDF reports);
# this copy also relates it to the stale-dependency check, which only the
# workflow runs.

TIMEBOMB_COUNT=$(jq_field '(.time_bombs // []) | length')
echo "## Time bombs (${TIMEBOMB_COUNT})"
echo
echo "_Any dependency, direct or transitive and not confirmed as test-only or outside the build,"
echo "that is archived upstream or has a CISA KEV-listed or CRITICAL CVE."
echo "Updating cannot fix an archived module, because upstream has stopped: it"
echo "has to be replaced or removed. It shows under Stale dependencies only when"
echo "it is a direct dependency that still has a newer release to take._"
echo
if [ "$TIMEBOMB_COUNT" -gt 0 ]; then
  echo "| Kind | Module | Detail | Reachability |"
  echo "|---|---|---|---|"
  jq_field '
    (.time_bombs // [])[]
    | "| \(.kind) | `\(.module)` | \(.detail) | \(.reachability // "—") |"
  '
else
  echo "(none)"
fi
echo

# --- Vulnerabilities worth acting on -----------------------------------------
#
# Ordered by exploitation evidence, not just severity: KEV membership first,
# then EPSS. A MEDIUM being exploited in the wild outranks a theoretical HIGH.

VULN_COUNT=$(jq_field '[.dependencies[]? | (.vulnerabilities // [])[]] | length')
if [ "$VULN_COUNT" -gt 0 ]; then
  KEV_COUNT=$(jq_field '[.dependencies[]? | (.vulnerabilities // [])[] | select(.in_kev == true)] | length')
  echo "## Vulnerabilities (${VULN_COUNT})"
  echo
  if [ "$KEV_COUNT" -gt 0 ]; then
    echo "> 🔴 **${KEV_COUNT} CVE(s) are in the CISA KEV catalog — confirmed exploited in the wild.**"
    echo
  fi
  echo "_Severity is the advisory's own; the grade also weighs reachability and"
  echo "test-only use. Sorted by exploitation evidence: KEV first, then EPSS._"
  echo
  echo "| ID | Severity | Module | Reachability | KEV | EPSS | Fix |"
  echo "|---|---|---|---|---|---|---|"
  jq -r --argjson max "$MAX_VULNS" '
    [ .dependencies[]?
      | .module as $m
      | (.vulnerabilities // [])[]
      | {
          id: .id,
          severity: (.severity // "UNKNOWN"),
          module: $m,
          reachability: (.reachability // "called"),
          kev: .in_kev,
          epss: .epss_score,
          fix: (.fixed_version // "")
        }
    ]
    | sort_by([(if .kev == true then 0 else 1 end), -(.epss // 0)])
    | .[0:$max][]
    | "| `\(.id)` | \(.severity) | `\(.module)` | \(.reachability) | \(if .kev == true then "🔴 yes" elif .kev == false then "no" else "not checked" end) | \(if .epss == null then "not checked" else ((.epss * 10000 | round / 100 | tostring) + "%") end) | \(if .fix != "" then "`" + .fix + "`" else "—" end) |"
  ' "$JSON"
  if [ "$VULN_COUNT" -gt "$MAX_VULNS" ]; then
    echo
    echo "_Showing ${MAX_VULNS} of ${VULN_COUNT}; full list in the \`unisupply.json\` artifact._"
  fi
  echo
fi

# --- Project -----------------------------------------------------------------

echo "## Project"
echo
jq_field '
  (.project // {}) as $p |
  "| Field | Value |\n|---|---|\n" +
  "| Module | `\($p.module // "—")` |\n" +
  "| Go version | \($p.go_version // "—") |\n" +
  "| Direct dependencies | \($p.direct_dependencies // "—") |\n" +
  "| Transitive dependencies | \($p.transitive_dependencies // "—") |\n" +
  "| Total dependencies | \($p.total_dependencies // "—") |"
'
echo

# --- Summary counts ----------------------------------------------------------

echo "## Summary"
echo
jq_field '
  (.summary // {}) as $s |
  ((.grade.rows // []) | map(.letter // "" | if . == "" then "-" else . end) | reduce .[] as $l ({}; .[$l] += 1)) as $by |
  "| Metric | Count |\n|---|---|\n" +
  "| Rows graded F | \($by["F"] // 0) |\n" +
  "| Rows graded D | \($by["D"] // 0) |\n" +
  "| Rows graded C | \($by["C"] // 0) |\n" +
  "| Rows graded B | \($by["B"] // 0) |\n" +
  "| Rows graded A | \($by["A"] // 0) |\n" +
  "| Rows with no letter (upkeep unread) | \($by["-"] // 0) |\n" +
  "| Total vulnerabilities | \($s.total_vulnerabilities // "—") |\n" +
  "| Unmaintained ≥1yr | \($s.unmaintained_1yr // "—") |\n" +
  "| Unmaintained ≥2yr | \($s.unmaintained_2yr // "—") |"
'
echo

# --- Worst grade rows --------------------------------------------------------
#
# The score column is a policy value shown for traceability: it picks the
# letter band and is not a measurement or a risk score.

echo "## Worst ${MAX_DEPS} grade rows"
echo
echo "| Module | Version | Grade | Score | Direct | Why |"
echo "|---|---|---|---|---|---|"
jq -r --argjson max "$MAX_DEPS" '
  (.grade.rows // [])
  | sort_by(-(.score // 0))
  | .[0:$max][]
  | "| `\(.module)`\(if .self == true then " (this module)" else "" end) | \(.version // "—") | \(if (.letter // "") == "" then "-" else (.letter + (if .estimated == true then "*" else "" end)) end) | \(.score // 0) | \(if .direct == true then "✅" else "—" end) | \(.reason // "") |"
' "$JSON"
echo

# --- Module integrity --------------------------------------------------------

# `module_directives` is emitted whenever the integrity scanner ran, including
# for a zero-finding scan, so its presence — not its finding count — decides
# whether this section renders. A clean scan and a scan that never ran are
# different results and must not render the same.
INTEGRITY_RAN=$(jq_field 'if .module_directives then "true" else "false" end')
if [ "$INTEGRITY_RAN" = "true" ]; then
  INTEGRITY_FINDINGS=$(jq_field '(.module_directives.findings // []) | length')
  # Redirects and checksum mismatches are the ones that change what code
  # ships; surface those and collapse the rest.
  SERIOUS=$(jq_field '
    [(.module_directives.findings // [])[]
     | select(.severity == "CRITICAL" or .severity == "HIGH")] | length
  ')
  echo "## Module integrity (${INTEGRITY_FINDINGS} finding(s))"
  echo
  jq_field '
    .module_directives as $m |
    "| Metric | Count |\n|---|---|\n" +
    "| `replace` directives | \($m.replace_count) |\n" +
    "| of which redirects | \($m.redirect_count) |\n" +
    "| `exclude` directives | \($m.exclude_count) |\n" +
    "| Pseudo-version pins | \($m.pseudo_version_count) |"
  '
  echo
  if [ "$SERIOUS" -gt 0 ]; then
    echo "| Severity | Category | Module | Detail |"
    echo "|---|---|---|---|"
    jq_field '
      (.module_directives.findings // [])[]
      | select(.severity == "CRITICAL" or .severity == "HIGH")
      | "| \(.severity) | \(.category) | `\(.module // "—")` | \(.detail) |"
    '
    echo
  fi
fi

# --- CI/CD and build-file findings -------------------------------------------

CI_FINDINGS=$(jq_field '((.ci_findings // []) + (.build_file_findings // [])) | length')
if [ "$CI_FINDINGS" -gt 0 ]; then
  echo "<details><summary><strong>CI/CD and build-file findings (${CI_FINDINGS})</strong></summary>"
  echo
  echo "| Severity | Rule | File | Line | Message |"
  echo "|---|---|---|---|---|"
  jq_field '
    ((.ci_findings // []) + (.build_file_findings // []))[]
    | "| \(.severity) | `\(.rule_id)` | `\(.file)` | \(.line // "—") | \(.message) |"
  '
  echo
  echo "</details>"
  echo
fi

# --- Warnings ----------------------------------------------------------------
#
# A degraded scan must not read like a clean one, so warnings are rendered
# rather than left in the JSON artifact.

WARNING_COUNT=$(jq_field '(.warnings // []) | length')
if [ "$WARNING_COUNT" -gt 0 ]; then
  echo "## ⚠️ Scan warnings (${WARNING_COUNT})"
  echo
  echo "_Data the scan could not collect. What could not be measured is never"
  echo "counted as clean: a check the grade needs that did not run makes it Pending._"
  echo
  jq -r --argjson max "$MAX_WARNINGS" '
    (.warnings // []) | .[0:$max][] | "- \(.)"
  ' "$JSON"
  if [ "$WARNING_COUNT" -gt "$MAX_WARNINGS" ]; then
    echo "- _…and $((WARNING_COUNT - MAX_WARNINGS)) more; see the \`unisupply.json\` artifact._"
  fi
  echo
fi

# --- Stale dependencies ------------------------------------------------------

echo "## Stale dependencies"
echo
echo "_Direct dependencies only (go.mod requirements without \`// indirect\`)"
echo "that have a newer version available; the second list narrows that to"
echo "pinned versions released more than 90 days ago, which is what the"
echo "\"Stale dependencies (>90d)\" row reports. Transitive dependencies and"
echo "modules with no newer release are never listed here, however old: see"
echo "Time bombs and the Summary's unmaintained counts._"
echo
echo "<details><summary><strong>Direct dependencies with available updates</strong></summary>"
echo
echo '```'
if [ -n "$STALE_DEPS" ] && [ -s "$STALE_DEPS" ]; then
  cat "$STALE_DEPS"
else
  echo "(none)"
fi
echo '```'
echo
echo "</details>"
echo
echo "<details><summary><strong>Dependencies older than 90 days</strong></summary>"
echo
echo '```'
if [ -n "$STALE_90" ] && [ -s "$STALE_90" ]; then
  cat "$STALE_90"
else
  echo "(none)"
fi
echo '```'
echo
echo "</details>"
