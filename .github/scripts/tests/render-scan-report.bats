#!/usr/bin/env bats
# Tests for .github/scripts/render-scan-report.sh
#
# The weekly issue lists stale dependencies and time bombs side by side, and
# they measure different things: stale covers direct dependencies behind an
# available update, time bombs cover any dependency not confirmed as test-only
# or outside the build that is archived or carries a KEV/CRITICAL CVE. Each section carries a note saying so, so a
# report with "no stale dependencies" next to an archived time bomb does not
# read as a contradiction.

SCRIPT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)/render-scan-report.sh"

setup() {
  WORK="$BATS_TEST_TMPDIR/work"
  mkdir -p "$WORK"
  JSON="$WORK/unisupply.json"
}

ARCHIVED_BOMB='{"time_bombs":[{"kind":"archived","module":"github.com/google/go-cmdtest","detail":"archived 53 months"}]}'

@test "time bombs section explains its scope and how archived modules relate to stale" {
  echo "$ARCHIVED_BOMB" > "$JSON"
  run "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [[ "$output" == *"## Time bombs (1)"* ]]
  [[ "$output" == *"Any dependency, direct or transitive and not confirmed as test-only or outside the build,"* ]]
  [[ "$output" == *"Updating cannot fix"* ]]
  [[ "$output" == *'`github.com/google/go-cmdtest`'* ]]
}

@test "time bombs note is rendered even when there are none" {
  echo '{}' > "$JSON"
  run "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [[ "$output" == *"## Time bombs (0)"* ]]
  [[ "$output" == *"Any dependency, direct or transitive and not confirmed as test-only or outside the build,"* ]]
}

@test "stale dependencies section states it covers direct dependencies only" {
  echo "$ARCHIVED_BOMB" > "$JSON"
  run "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [[ "$output" == *"## Stale dependencies"* ]]
  [[ "$output" == *"Direct dependencies only"* ]]
  [[ "$output" == *"Transitive dependencies and"* ]]
}

@test "stale lists still render their contents" {
  echo '{}' > "$JSON"
  echo "golang.org/x/mod v0.37.0 → v0.38.0" > "$WORK/stale-deps.txt"
  echo "STALE(120 days): golang.org/x/mod v0.37.0" > "$WORK/stale-90.txt"
  run "$SCRIPT" "$JSON" "$WORK/stale-deps.txt" "$WORK/stale-90.txt"
  [ "$status" -eq 0 ]
  [[ "$output" == *"golang.org/x/mod v0.37.0 → v0.38.0"* ]]
  [[ "$output" == *"STALE(120 days): golang.org/x/mod v0.37.0"* ]]
}

# The fixtures below are the v2 JSON shape: .grade.letter, .grade.pending, .grade.deciding and .grade.rows[].
# v2-pending.json is the real output of `unisupply --offline --module-version v1.0.0 -f json` on a one-dependency
# module; v2-f.json is that output edited by hand into a graded F with one called critical finding.
FIXTURES="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/fixtures"

@test "pending grade renders PENDING, the check that did not run, and letterless rows as '-'" {
  run "$SCRIPT" "$FIXTURES/v2-pending.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"## Grade"* ]]
  [[ "$output" == *"PENDING (no letter)"* ]]
  [[ "$output" == *'check `vulnerability_scan` did not run'* ]]
  [[ "$output" == *"| Rows with no letter (upkeep unread) | 2 |"* ]]
  [[ "$output" == *'| `gopkg.in/ini.v1` | v1.67.0 | - | 0 |'* ]]
}

@test "graded F renders the letter, the deciding row, the rows table and the vulnerability" {
  run "$SCRIPT" "$FIXTURES/v2-f.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"**🔴 F**"* ]]
  [[ "$output" == *'> **F** decided by `gopkg.in/ini.v1` — called critical finding GO-2026-0001'* ]]
  [[ "$output" == *"| Rows graded F | 1 |"* ]]
  [[ "$output" == *'| `gopkg.in/ini.v1` | v1.67.0 | F | 90 | ✅ | called critical finding GO-2026-0001 |'* ]]
  [[ "$output" == *'| `example.com/sample` (this module) | v1.0.0 | A | 0 |'* ]]
  [[ "$output" == *'`GO-2026-0001`'* ]]
}

@test "no removed v1 field is rendered" {
  for f in v2-pending v2-f; do
    run "$SCRIPT" "$FIXTURES/$f.json"
    [ "$status" -eq 0 ]
    [[ "$output" != *"Overall risk"* ]]
    [[ "$output" != *"risk level"* ]]
    [[ "$output" != *"Takeover"* ]]
    [[ "$output" != *"Critical risk"* ]]
    [[ "$output" != *"Risk factors"* ]]
  done
}

@test "an estimated letter keeps its star and a missing grade is not a letter" {
  jq '.grade.estimated = true | .grade.letter = "C" | del(.grade.pending) | del(.grade.deciding)' "$FIXTURES/v2-f.json" > "$JSON"
  run "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [[ "$output" == *"**🟡 C*"* ]]

  echo '{}' > "$JSON"
  run "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no grade (grading was not run)"* ]]
}
