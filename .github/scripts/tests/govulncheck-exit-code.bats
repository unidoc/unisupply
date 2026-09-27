#!/usr/bin/env bats
# Tests for .github/scripts/govulncheck-exit-code.sh
#
# Each test writes a minimal govulncheck JSON stream to a tmpdir and checks the
# exit code the script recovers from it. The fixtures follow the shape
# govulncheck v1.1.4 writes with `-format json`: a stream of top-level objects,
# opening with `config`, where a finding's trace[0] carries `function` only for
# symbol-level (reachable) findings, `package` for package-level ones, and just
# `module` for module-level ones.

SCRIPT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)/govulncheck-exit-code.sh"

# `run --separate-stderr` keeps the printed code apart from the diagnostics.
bats_require_minimum_version 1.5.0

setup() {
  WORK="$BATS_TEST_TMPDIR/work"
  mkdir -p "$WORK"
  JSON="$WORK/govulncheck.json"
}

# write_stream <finding objects...>: a config message followed by the given
# finding messages, one object per line as govulncheck emits them.
write_stream() {
  {
    echo '{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.4"}}'
    echo '{"progress":{"message":"Scanning your code across 27 dependent modules for known vulnerabilities..."}}'
    local f
    for f in "$@"; do
      echo "$f"
    done
  } > "$JSON"
}

SYMBOL_FINDING='{"finding":{"osv":"GO-2026-5026","fixed_version":"v1.25.13","trace":[{"module":"stdlib","version":"v1.25.10","package":"net/http","function":"Head"},{"module":"github.com/example/app","package":"github.com/example/app","function":"main"}]}}'
PACKAGE_FINDING='{"finding":{"osv":"GO-2026-4970","fixed_version":"v1.25.12","trace":[{"module":"stdlib","version":"v1.25.10","package":"os"}]}}'
MODULE_FINDING='{"finding":{"osv":"GO-2026-5932","trace":[{"module":"golang.org/x/crypto","version":"v0.57.0"}]}}'

@test "symbol-level finding yields 3 and names the advisory on stderr" {
  write_stream "$MODULE_FINDING" "$SYMBOL_FINDING"
  run --separate-stderr "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [ "$output" = "3" ]
  [[ "$stderr" == *"GO-2026-5026"* ]]
}

@test "package- and module-level findings alone yield 0" {
  write_stream "$PACKAGE_FINDING" "$MODULE_FINDING"
  run --separate-stderr "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [ "$output" = "0" ]
}

@test "a stream with no findings yields 0" {
  write_stream
  run --separate-stderr "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [ "$output" = "0" ]
}

@test "an empty function name is not treated as reachable" {
  write_stream '{"finding":{"osv":"GO-2026-0001","trace":[{"module":"stdlib","package":"os","function":""}]}}'
  run --separate-stderr "$SCRIPT" "$JSON"
  [ "$status" -eq 0 ]
  [ "$output" = "0" ]
}

@test "missing file exits 2 without printing a code" {
  run --separate-stderr "$SCRIPT" "$WORK/does-not-exist.json"
  [ "$status" -eq 2 ]
  [ -z "$output" ]
}

@test "empty file exits 2 without printing a code" {
  : > "$JSON"
  run --separate-stderr "$SCRIPT" "$JSON"
  [ "$status" -eq 2 ]
  [ -z "$output" ]
}

@test "malformed JSON exits 2 without printing a code" {
  printf '{"config":{}}\n{"finding":' > "$JSON"
  run --separate-stderr "$SCRIPT" "$JSON"
  [ "$status" -eq 2 ]
  [ -z "$output" ]
}

@test "valid JSON without a config message exits 2" {
  echo '{"finding":{"osv":"GO-2026-5026","trace":[{"module":"stdlib","function":"Head"}]}}' > "$JSON"
  run --separate-stderr "$SCRIPT" "$JSON"
  [ "$status" -eq 2 ]
  [ -z "$output" ]
}

@test "no argument exits 2 with usage" {
  run --separate-stderr "$SCRIPT"
  [ "$status" -eq 2 ]
  [[ "$stderr" == *"usage:"* ]]
}
