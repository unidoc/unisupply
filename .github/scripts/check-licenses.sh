#!/usr/bin/env bash
# Fail if any dep carries a non-permissive license that isn't already
# documented in THIRD_PARTY_LICENSES.md.
#
# Requires: go-licenses v2 (go install github.com/google/go-licenses/v2@v2.0.1)
# Uses `report` (CSV output). go-licenses exits 0 even for Unknown licenses
# (logged to stderr); Unknown rows are caught by the allowlist check below.
set -euo pipefail

ALLOWLIST="MIT BSD-2-Clause BSD-3-Clause Apache-2.0 ISC"
INVENTORY="THIRD_PARTY_LICENSES.md"

# Guard: inventory must exist before we do anything else.
[[ -f "$INVENTORY" ]] || { echo "ERROR: $INVENTORY not found — create it before running this check" >&2; exit 1; }

# Build an exact list of module paths mentioned in the inventory.
# Exact matching prevents cross-major-version collisions (e.g. unipdf/v3
# substring-matching a future unipdf/v4 entry) and cross-section collisions
# (commercial vs. permissive rows both matching the same grep).
mapfile -t INVENTORY_MODULES < <(
  grep -oE '(github\.com|golang\.org/x|gopkg\.in)/[a-zA-Z0-9._/-]+' "$INVENTORY" | sort -u
)

CSV=$(go-licenses report github.com/unidoc/unisupply/cmd/unisupply)
if [[ -z "$CSV" ]]; then
  echo "ERROR: go-licenses produced no output — check installation and module path" >&2
  exit 1
fi

FAILED=0
while IFS=',' read -r module _url license; do
  [[ -z "$module" ]] && continue

  # go-licenses reports package paths (e.g. github.com/unidoc/unipdf/v3/common)
  # but the inventory lists module roots (e.g. github.com/unidoc/unipdf/v3).
  # Walk up the path until we find an exact match or exhaust all components.
  in_inventory=0
  m="$module"
  while [[ "$m" == */* ]]; do
    for entry in "${INVENTORY_MODULES[@]}"; do
      [[ "$m" == "$entry" ]] && in_inventory=1 && break 2
    done
    m="${m%/*}"
  done
  [[ $in_inventory -eq 1 ]] && continue

  # Skip if license is in the allowlist.
  ok=0
  for allowed in $ALLOWLIST; do
    [[ "$license" == "$allowed" ]] && ok=1 && break
  done
  if [[ $ok -eq 0 ]]; then
    echo "UNLISTED OR UNKNOWN LICENSE: $module ($license)" >&2
    FAILED=1
  fi
done <<< "$CSV"

if [[ $FAILED -eq 1 ]]; then
  echo "" >&2
  echo "Add the above modules to THIRD_PARTY_LICENSES.md and document their terms." >&2
  exit 1
fi

# Reverse check: warn on inventory entries no longer present in the dep graph.
# Uses substring match (module root against package paths) — intentional, since
# go-licenses reports package-level paths, not module roots.
for entry in "${INVENTORY_MODULES[@]}"; do
  # Skip the module being scanned itself (appears in the inventory's code block).
  [[ "$entry" == github.com/unidoc/unisupply* ]] && continue
  if ! grep -qF "$entry" <<< "$CSV"; then
    echo "STALE INVENTORY ENTRY: $entry is listed in $INVENTORY but not found in the dep graph" >&2
  fi
done

# ---------------------------------------------------------------------------
# NOTICE file sweep (Apache 2.0 §4(d) compliance)
#
# Walk the binary's actual import set (not go list -m all, which includes
# test-only and graph-only modules we don't ship) and fail if any dep ships
# a NOTICE file that isn't covered in the repo-root NOTICE, with an exact
# path+version match to catch upgrades as well as additions.
# ---------------------------------------------------------------------------
REPO_NOTICE="NOTICE"
[[ -f "$REPO_NOTICE" ]] || { echo "ERROR: repo-root $REPO_NOTICE not found" >&2; exit 1; }

# Collect "dir canonical-path version" triples for every module in the compiled
# binary. Using go list to extract path and version avoids the filesystem
# case-encoding issue where e.g. github.com/Azure/... is stored on disk as
# github.com/!azure/... — the canonical form is what belongs in the repo NOTICE.
# Omit 2>/dev/null so resolution errors fail loud rather than silently
# producing an empty list that would pass the check incorrectly.
mapfile -t MOD_ENTRIES < <(
  go list -deps -f '{{with .Module}}{{if .Dir}}{{.Dir}} {{.Path}} {{.Version}}{{end}}{{end}}' ./cmd/unisupply/ \
    | sort -u | grep -v '^$'
)
if [[ ${#MOD_ENTRIES[@]} -eq 0 ]]; then
  echo "ERROR: go list produced no module entries — check module resolution" >&2
  exit 1
fi

REPO_ROOT=$(pwd)
NOTICE_FAILED=0
for entry in "${MOD_ENTRIES[@]}"; do
  dir="${entry%% *}"
  rest="${entry#* }"
  mod_path="${rest%% *}"
  mod_version="${rest##* }"

  # Skip the repo itself.
  [[ "$dir" == "$REPO_ROOT" ]] && continue

  notice_file=""
  for candidate in NOTICE NOTICE.txt NOTICE.md; do
    [[ -f "$dir/$candidate" ]] && notice_file="$dir/$candidate" && break
  done
  [[ -z "$notice_file" ]] && continue

  # The repo NOTICE must contain a single line with both the canonical module
  # path and version (e.g. "gopkg.in/yaml.v3 v3.0.1"). A same-line match
  # catches both missing entries and version drift from upgrades.
  if ! grep -qF "$mod_path $mod_version" "$REPO_NOTICE"; then
    echo "UNCOVERED NOTICE: $mod_path $mod_version ships a NOTICE file not reflected in repo-root NOTICE" >&2
    NOTICE_FAILED=1
  fi
done

if [[ $NOTICE_FAILED -eq 1 ]]; then
  echo "" >&2
  echo "Update the repo-root NOTICE file to include the module path and version listed above." >&2
  echo "See the \"Apache NOTICE compliance\" section in CONTRIBUTING.md for guidance." >&2
  exit 1
fi

echo "License check passed."
