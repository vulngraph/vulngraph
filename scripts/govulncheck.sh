#!/usr/bin/env bash
# Run govulncheck and fail only on symbol-level findings, minus reviewed
# exceptions in .github/govulncheck-allow.txt (govulncheck has no suppression
# flag).
#
#   scripts/govulncheck.sh                 # source mode: reachability analysis
#   scripts/govulncheck.sh bin/graph       # binary mode: symbols in the binary
#
# CI uses binary mode: source mode builds a whole-program call graph over
# nuclei + every cloud SDK and peaks near 20 GB RSS, more than a standard
# GitHub runner has; binary mode needs ~400 MB. Binary mode is stricter (it
# flags any vulnerable symbol linked in, reachable or not).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allow="$root/.github/govulncheck-allow.txt"
cd "$root"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
kind="reachable"
if [ $# -gt 0 ]; then
  kind="linked (binary mode, reachability not analysed)"
  govulncheck -mode=binary -format json "$1" > "$out"
else
  govulncheck -format json ./... > "$out"
fi

found="$(jq -r 'select(.finding and .finding.trace[0].function) | .finding.osv' "$out" | sort -u)"
allowed="$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$allow" 2>/dev/null | awk '{print $1}' | sort -u)"
blocking="$(comm -23 <(printf '%s\n' "$found" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d'))"

if [ -n "$found" ]; then
  echo "Vulnerable symbols $kind: $(echo "$found" | tr '\n' ' ')"
fi
if [ -n "$blocking" ]; then
  echo "Not allowlisted — fix or review into $allow:" >&2
  if [ $# -gt 0 ]; then govulncheck -mode=binary "$1" || true; else govulncheck ./... || true; fi
  exit 1
fi
echo "govulncheck: no unreviewed $kind vulnerable symbols"
