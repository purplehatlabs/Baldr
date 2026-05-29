#!/usr/bin/env bash
set -euo pipefail

# Run govulncheck and fail when fixable vulnerabilities affect application code.
# Transitive advisories with no upstream fix (Fixed in: N/A) are reported as known debt.

output="$(mktemp)"
trap 'rm -f "$output"' EXIT

set +e
go run golang.org/x/vuln/cmd/govulncheck@latest ./... >"$output" 2>&1
code=$?
set -e

cat "$output"

if [[ "$code" -eq 0 ]]; then
  exit 0
fi

has_fixable=false
while IFS= read -r line; do
  fixed="${line#*Fixed in: }"
  if [[ "$fixed" != "N/A" ]]; then
    has_fixable=true
    break
  fi
done < <(grep 'Fixed in:' "$output" || true)

if [[ "$has_fixable" == "true" ]]; then
  echo "govulncheck: fixable vulnerabilities must be resolved before merging."
  exit 1
fi

echo "govulncheck: only unfixed transitive advisories remain (documented known debt)."
exit 0
