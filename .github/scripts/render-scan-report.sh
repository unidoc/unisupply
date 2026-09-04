#!/usr/bin/env bash
#
# Render a unisupply JSON report as markdown, for both the workflow job
# summary and the weekly security issue body.
#
# One renderer for both consumers, on purpose: a headline number is not a
# report, so both carry the same attribution, time bombs and per-dependency
# risk factors, and neither can drift away from the other.
#
# Usage:
#   render-scan-report.sh <unisupply.json> [stale-deps.txt] [stale-90.txt]
#
# Environment (all optional):
#   GOVULNCHECK_RC  govulncheck exit code (3 = reachable vulnerability found)
#   STALE           "true" when dependencies older than 90 days were found
#   AUDIT_RESULT    result of the audit job, when the caller knows it
#   MAX_DEPS        rows in the risky-dependency table (default 10)
#   MAX_VULNS       rows in the vulnerability table (default 15)
#   MAX_TAKEOVERS   rows in the takeover-candidate list (default 20)
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
MAX_TAKEOVERS="${MAX_TAKEOVERS:-20}"
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

# --- Risk --------------------------------------------------------------------

LEVEL=$(jq_field '.overall_risk_level // "UNKNOWN"')
SCORE=$(jq_field '.overall_risk_score // "?"')

case "$LEVEL" in
  LOW)      LEVEL_BADGE="🟢 LOW" ;;
  MEDIUM)   LEVEL_BADGE="🟡 MEDIUM" ;;
  HIGH)     LEVEL_BADGE="🟠 HIGH" ;;
  CRITICAL) LEVEL_BADGE="🔴 CRITICAL" ;;
  *)        LEVEL_BADGE="⚪ $LEVEL" ;;
esac

case "${GOVULNCHECK_RC:-}" in
  0)  GOVULN_BADGE="🟢 0 — no vulnerabilities" ;;
  3)  GOVULN_BADGE="🔴 3 — call-graph-reachable vulnerability found" ;;
  "") GOVULN_BADGE="⚪ (not run)" ;;
  *)  GOVULN_BADGE="🟠 ${GOVULNCHECK_RC} — tool error" ;;
esac

echo "## Risk"
echo
echo "| Field | Value |"
echo "|---|---|"
echo "| Overall risk level | ${LEVEL_BADGE} |"
echo "| Overall risk score | **${SCORE}** / 100 |"
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

WORST_CVE=$(jq_field '.worst_cve_id // ""')
if [ -n "$WORST_CVE" ]; then
  WORST_SEV=$(jq_field '.worst_cve_severity // "UNKNOWN"')
  # "scored": after reachability and test-only downgrades. The table below
  # reports each advisory's source severity, which can be higher.
  echo "| Worst CVE | \`${WORST_CVE}\` (scored ${WORST_SEV}) |"
fi
echo

# "Why this risk level". A headline can be HIGH while every dependency scores
# MEDIUM, because a floor rule fired; without the driver the number looks
# arbitrary or wrong.
UNSCORED=$(jq_field '.headline_unscored_reason // ""')
DRIVER=$(jq_field '.headline.driver // ""')
if [ -n "$UNSCORED" ]; then
  echo "> **${LEVEL} (${SCORE})** — not scored: ${UNSCORED}"
  echo
elif [ -n "$DRIVER" ]; then
  DRIVING_ITEM=$(jq_field '.headline.driving_item // ""')
  DRIVER_REASON=$(jq_field '.headline.reason // ""')
  LINE="> **${LEVEL} (${SCORE})** driven by \`${DRIVER}\`"
  if [ -n "$DRIVING_ITEM" ]; then
    LINE="${LINE}: \`${DRIVING_ITEM}\`"
  fi
  if [ -n "$DRIVER_REASON" ]; then
    LINE="${LINE} — ${DRIVER_REASON}"
  fi
  echo "$LINE"
  echo
fi

# --- Time bombs --------------------------------------------------------------
#
# Never inside <details>. These exist to be undeniable.

TIMEBOMB_COUNT=$(jq_field '(.time_bombs // []) | length')
echo "## Time bombs (${TIMEBOMB_COUNT})"
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
  echo "_Severity is the advisory's own; the score may downgrade it for"
  echo "reachability or test-only use. Sorted by exploitation evidence: KEV"
  echo "first, then EPSS._"
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
  "| Metric | Count |\n|---|---|\n" +
  "| Critical risk | \($s.critical_risk_count // "—") |\n" +
  "| High risk | \($s.high_risk_count // "—") |\n" +
  "| Medium risk | \($s.medium_risk_count // "—") |\n" +
  "| Low risk | \($s.low_risk_count // "—") |\n" +
  "| Total vulnerabilities | \($s.total_vulnerabilities // "—") |\n" +
  "| Unmaintained ≥1yr | \($s.unmaintained_1yr // "—") |\n" +
  "| Unmaintained ≥2yr | \($s.unmaintained_2yr // "—") |"
'
echo

# --- Top risky dependencies --------------------------------------------------

echo "## Top ${MAX_DEPS} risky dependencies"
echo
echo "| Module | Version | Level | Score | Direct | Risk factors |"
echo "|---|---|---|---|---|---|"
jq -r --argjson max "$MAX_DEPS" '
  (.dependencies // [])
  | sort_by(-.risk_score)
  | .[0:$max][]
  | "| `\(.module)` | \(.version) | \(.risk_level) | \(.risk_score) | \(if .direct then "✅" else "—" end) | \((.risk_factors // []) | join(", ")) |"
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

# --- Takeover candidates -----------------------------------------------------

TAKEOVER_COUNT=$(jq_field '(.takeover_candidates // []) | length')
if [ "$TAKEOVER_COUNT" -gt 0 ]; then
  echo "<details><summary><strong>Takeover candidates (${TAKEOVER_COUNT})</strong></summary>"
  echo
  jq -r --argjson max "$MAX_TAKEOVERS" '
    (.takeover_candidates // [])
    | .[0:$max][]
    | "- `\(.owner)/\(.repo)` — \(.reason) (stars \(.stars), bus factor \(.bus_factor), \(.activity_pattern))"
  ' "$JSON"
  if [ "$TAKEOVER_COUNT" -gt "$MAX_TAKEOVERS" ]; then
    echo
    echo "_Showing ${MAX_TAKEOVERS} of ${TAKEOVER_COUNT}._"
  fi
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
  echo "_Data the scan could not collect. Axes it could not measure are excluded"
  echo "from scoring rather than counted as clean._"
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
