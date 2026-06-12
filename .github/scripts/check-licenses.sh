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

CSV=$(go-licenses report github.com/unidoc/unisupply/cmd/unisupply 2>/dev/null)

FAILED=0
while IFS=',' read -r module _url license; do
  [[ -z "$module" ]] && continue

  # go-licenses reports package paths (e.g. github.com/unidoc/unipdf/v3/common)
  # but the inventory lists module roots (e.g. github.com/unidoc/unipdf/v3).
  # Walk up the path until we find a match or exhaust all components.
  in_inventory=0
  m="$module"
  while [[ "$m" == */* ]]; do
    if grep -qF "$m" "$INVENTORY"; then
      in_inventory=1; break
    fi
    m="${m%/*}"
  done
  [[ $in_inventory -eq 1 ]] && continue

  # Skip if license is in the allowlist
  ok=0
  for allowed in $ALLOWLIST; do
    [[ "$license" == "$allowed" ]] && ok=1 && break
  done
  if [[ $ok -eq 0 ]]; then
    echo "UNLISTED NON-PERMISSIVE: $module ($license)" >&2
    FAILED=1
  fi
done <<< "$CSV"

if [[ $FAILED -eq 1 ]]; then
  echo "" >&2
  echo "Add the above modules to THIRD_PARTY_LICENSES.md and document their terms." >&2
  exit 1
fi
echo "License check passed."
