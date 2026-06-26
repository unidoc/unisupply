#!/usr/bin/env bats
# Tests for the NOTICE sweep in .github/scripts/check-licenses.sh
#
# Strategy: every test runs from a tmpdir that has the minimal state to pass
# the license-allowlist section (THIRD_PARTY_LICENSES.md + go-licenses stub),
# then exercises one specific NOTICE-sweep failure path.
#
# All calls to `go` and `go-licenses` are intercepted by stub scripts placed
# at the front of PATH — no real module resolution or network access required.

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
