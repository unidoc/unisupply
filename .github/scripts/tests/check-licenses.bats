#!/usr/bin/env bats
# Tests for the NOTICE sweep in .github/scripts/check-licenses.sh
#
# Strategy: every test runs from a tmpdir that has the minimal state to pass
# the license-allowlist section (THIRD_PARTY_LICENSES.md + go-licenses stub),
# then exercises one specific NOTICE-sweep failure path.
#
# All calls to `go` and `go-licenses` are intercepted by stub scripts placed
# at the front of PATH — no real module resolution or network access required.
#
# Stub contract — go: check-licenses.sh calls
#   go list -deps -f '{{with .Module}}{{if .Dir}}{{.Dir}} {{.Path}} {{.Version}}{{end}}{{end}}' ./cmd/unisupply/
# and parses '<dir> <path> <version>' triples from the output.
# The stub returns whatever GO_LIST_OUTPUT contains when $1 == "list".
# If check-licenses.sh changes its go invocation (format template, package
# selector, flags), the stub must be updated to match.
#
# Stub contract — go-licenses: check-licenses.sh calls
#   go-licenses report github.com/unidoc/unisupply/cmd/unisupply
# and parses '<module>,<url>,<license>' CSV rows.
# The stub ignores all arguments and always emits the row(s) set up by each
# test. If check-licenses.sh changes its go-licenses subcommand or package
# path, the stub must be updated to match.

SCRIPT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)/check-licenses.sh"

setup() {
  # Skip on bash < 4: check-licenses.sh requires bash 4+ (mapfile). Without this
  # guard, tests 2-5 pass vacuously on stock macOS bash 3.2 because the script's
  # version check exits 1 before any NOTICE sweep logic runs.
  if (( BASH_VERSINFO[0] < 4 )); then
    skip "bash 4+ required to run check-licenses.sh (got ${BASH_VERSION})"
  fi

  # Scratch dir for this test; bats cleans it up automatically.
  WORK="$BATS_TEST_TMPDIR/work"
  mkdir -p "$WORK"

  # Minimal THIRD_PARTY_LICENSES.md so the allowlist section passes.
  cat > "$WORK/THIRD_PARTY_LICENSES.md" <<'EOF'
## Third-party licenses

- github.com/some/lib — MIT
EOF

  # Stub dir: put before PATH so every `go` and `go-licenses` call is intercepted.
  STUBS="$BATS_TEST_TMPDIR/stubs"
  mkdir -p "$STUBS"

  # go-licenses stub: emits one MIT row — allowlist section passes, nothing else matters.
  cat > "$STUBS/go-licenses" <<'EOF'
#!/usr/bin/env bash
echo "github.com/some/lib,https://example.com/LICENSE,MIT"
EOF
  chmod +x "$STUBS/go-licenses"

  # Default `go` stub: empty output (overridden per test via GO_LIST_OUTPUT env var).
  # The test sets GO_LIST_OUTPUT to control what `go list` returns.
  cat > "$STUBS/go" <<'EOF'
#!/usr/bin/env bash
if [[ "${1-}" == "list" ]]; then
  printf '%s\n' "${GO_LIST_OUTPUT:-}"
  exit 0
fi
echo "go stub: unexpected subcommand '$*' — update the stub if check-licenses.sh gains new go calls" >&2
exit 1
EOF
  chmod +x "$STUBS/go"

  export PATH="$STUBS:$PATH"
}

# ---------------------------------------------------------------------------
# Helper: write a fake module dir with a NOTICE file.
# Prints the dir path so the caller can capture it.
# ---------------------------------------------------------------------------
make_mod_dir() {
  local dir="$BATS_TEST_TMPDIR/mods/$1"
  mkdir -p "$dir"
  echo "NOTICE content for $1" > "$dir/NOTICE"
  echo "$dir"
}

# ---------------------------------------------------------------------------
# 1. Happy path — dep NOTICE covered in repo NOTICE.
# ---------------------------------------------------------------------------
@test "passes when dep NOTICE is covered in repo NOTICE" {
  mod_dir="$(make_mod_dir "happy")"

  cat > "$WORK/NOTICE" <<EOF
unisupply
Copyright © UniDoc ehf

github.com/happy/mod v1.2.3
EOF

  export GO_LIST_OUTPUT="$mod_dir github.com/happy/mod v1.2.3"

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"License check passed"* ]]
}

# ---------------------------------------------------------------------------
# 2. Dep ships a NOTICE not mentioned in repo NOTICE at all.
# ---------------------------------------------------------------------------
@test "fails when dep ships NOTICE not in repo NOTICE" {
  mod_dir="$(make_mod_dir "uncovered")"

  # Repo NOTICE deliberately does NOT mention github.com/uncovered/mod.
  cat > "$WORK/NOTICE" <<'EOF'
unisupply
Copyright © UniDoc ehf
EOF

  export GO_LIST_OUTPUT="$mod_dir github.com/uncovered/mod v1.0.0"

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"UNCOVERED NOTICE"* ]]
}

# ---------------------------------------------------------------------------
# 3. Version drift — repo NOTICE has the old version.
# ---------------------------------------------------------------------------
@test "fails when dep version drifts from repo NOTICE entry" {
  mod_dir="$(make_mod_dir "drift")"

  # Repo NOTICE has v1.0.0 but go list reports v2.0.0.
  cat > "$WORK/NOTICE" <<'EOF'
unisupply
Copyright © UniDoc ehf

github.com/drift/mod v1.0.0
EOF

  export GO_LIST_OUTPUT="$mod_dir github.com/drift/mod v2.0.0"

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"UNCOVERED NOTICE"* ]]
}

# ---------------------------------------------------------------------------
# 4. go list returns empty — resolution error.
# ---------------------------------------------------------------------------
@test "fails when go list returns empty" {
  cat > "$WORK/NOTICE" <<'EOF'
unisupply
Copyright © UniDoc ehf
EOF

  export GO_LIST_OUTPUT=""

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"go list produced no module entries"* ]]
}

# ---------------------------------------------------------------------------
# 5. Repo-root NOTICE file is missing entirely.
# ---------------------------------------------------------------------------
@test "fails when repo-root NOTICE is missing" {
  # No NOTICE file created in WORK — script should catch this at line 85.
  # go list stub output is irrelevant; execution never reaches it.
  mod_dir="$(make_mod_dir "norepo")"
  export GO_LIST_OUTPUT="$mod_dir github.com/norepo/mod v1.0.0"

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"repo-root NOTICE not found"* ]]
}

# ---------------------------------------------------------------------------
# 6. THIRD_PARTY_LICENSES.md is missing entirely.
# ---------------------------------------------------------------------------
@test "fails when THIRD_PARTY_LICENSES.md is missing" {
  # setup() creates THIRD_PARTY_LICENSES.md — remove it to hit the guard at
  # the top of the script before any license scanning begins.
  rm "$WORK/THIRD_PARTY_LICENSES.md"

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"THIRD_PARTY_LICENSES.md not found"* ]]
}

# ---------------------------------------------------------------------------
# 7. go-licenses produces no output — installation or module error.
# ---------------------------------------------------------------------------
@test "fails when go-licenses produces no output" {
  # Override the go-licenses stub to emit nothing.
  cat > "$BATS_TEST_TMPDIR/stubs/go-licenses" <<'EOF'
#!/usr/bin/env bash
EOF
  chmod +x "$BATS_TEST_TMPDIR/stubs/go-licenses"

  cat > "$WORK/NOTICE" <<'EOF'
unisupply
Copyright © UniDoc ehf
EOF

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"go-licenses produced no output"* ]]
}

# ---------------------------------------------------------------------------
# 8. Dep carries a non-allowlist license not covered by the inventory.
# ---------------------------------------------------------------------------
@test "fails when dep has a non-allowlist license not in inventory" {
  # Override go-licenses stub to emit a GPL-3.0 row for a module that is not
  # in the inventory (inventory only lists github.com/some/lib).
  cat > "$BATS_TEST_TMPDIR/stubs/go-licenses" <<'EOF'
#!/usr/bin/env bash
echo "github.com/evil/pkg,https://example.com/LICENSE,GPL-3.0"
EOF
  chmod +x "$BATS_TEST_TMPDIR/stubs/go-licenses"

  cat > "$WORK/NOTICE" <<'EOF'
unisupply
Copyright © UniDoc ehf
EOF

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"UNLISTED OR UNKNOWN LICENSE"* ]]
}

# ---------------------------------------------------------------------------
# 9. Inventory lists a module no longer in the dep graph — stale warning.
# ---------------------------------------------------------------------------
@test "warns on stale inventory entry (exits 0)" {
  # go-licenses returns github.com/other/pkg (MIT, in allowlist) but NOT
  # github.com/some/lib, which is in THIRD_PARTY_LICENSES.md. The script
  # emits a STALE INVENTORY ENTRY warning but does not fail.
  cat > "$BATS_TEST_TMPDIR/stubs/go-licenses" <<'EOF'
#!/usr/bin/env bash
echo "github.com/other/pkg,https://example.com/LICENSE,MIT"
EOF
  chmod +x "$BATS_TEST_TMPDIR/stubs/go-licenses"

  # Point go list at a mod dir with no NOTICE file so the NOTICE sweep
  # passes (no NOTICE → nothing to cover, loop skips it).
  mod_dir="$BATS_TEST_TMPDIR/mods/stale"
  mkdir -p "$mod_dir"
  export GO_LIST_OUTPUT="$mod_dir github.com/other/pkg v1.0.0"

  cat > "$WORK/NOTICE" <<'EOF'
unisupply
Copyright © UniDoc ehf
EOF

  cd "$WORK"
  run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"STALE INVENTORY ENTRY"* ]]
}
