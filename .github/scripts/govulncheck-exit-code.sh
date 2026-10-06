#!/usr/bin/env bash
#
# Recover govulncheck's text-mode exit code from its JSON output.
#
# `govulncheck -format json` exits 0 whether or not it finds anything; only
# text mode exits 3 for a reachable vulnerability. The weekly workflow keeps
# the JSON (it is an uploaded artifact) but also needs that exit code: it
# drives the job-summary badge and is one of the conditions for filing the
# weekly issue.
#
# A vulnerability is reachable when a finding's first trace frame names a
# function — a symbol-level finding, which is what text mode counts under
# "Your code is affected by N vulnerabilities". Package- and module-level
# findings leave the code at 0, as they do in text mode.
#
# Usage:
#   govulncheck-exit-code.sh <govulncheck.json>
#
# Prints 3 when at least one reachable vulnerability is found, 0 otherwise,
# and names the reachable advisories on stderr. Exits 2 without printing a
# code when the file is missing, empty or not a govulncheck JSON stream, so a
# broken run is never reported as clean.

# The jq program is single-quoted on purpose; nothing is interpolated into it.
# shellcheck disable=SC2016
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <govulncheck.json>" >&2
  exit 2
fi
json="$1"

if [[ ! -s "$json" ]]; then
  echo "ERROR: $json is missing or empty" >&2
  exit 2
fi

# govulncheck writes a stream of top-level objects; -s collects them into one
# array. Every stream opens with a `config` message naming the scanner
# (govulncheck sets scanner_name from its build info), so a stream without one
# that says govulncheck did not come from govulncheck.
if ! reachable=$(jq -r -s '
    if any(.[]; type == "object" and (.config | type == "object")
                and .config.scanner_name == "govulncheck") | not then
      error("no govulncheck config message")
    else . end
    | [.[] | select(type == "object" and has("finding")) | .finding
       | select((.trace[0].function // "") != "") | .osv]
    | unique | join(" ")
  ' "$json" 2>/dev/null); then
  echo "ERROR: $json is not a govulncheck JSON stream" >&2
  exit 2
fi

if [[ -n "$reachable" ]]; then
  echo "reachable vulnerabilities: $reachable" >&2
  echo 3
else
  echo 0
fi
