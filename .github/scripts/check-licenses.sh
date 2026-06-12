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

echo "License check passed."
