#!/usr/bin/env bats
# Tests for .github/scripts/render-scan-report.sh
#
# The weekly issue lists stale dependencies and time bombs side by side, and
# they measure different things: stale covers direct dependencies behind an
# available update, time bombs cover any non-test dependency that is archived
# or carries a KEV/CRITICAL CVE. Each section carries a note saying so, so a
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
  [[ "$output" == *"Any non-test dependency, direct or transitive"* ]]
  [[ "$output" == *"Updating cannot fix"* ]]
  [[ "$output" == *'`github.com/google/go-cmdtest`'* ]]
}

@test "time bombs note is rendered even when there are none" {
  echo '{}' > "$JSON"
  run "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [[ "$output" == *"## Time bombs (0)"* ]]
  [[ "$output" == *"Any non-test dependency, direct or transitive"* ]]
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
