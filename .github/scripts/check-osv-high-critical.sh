#!/usr/bin/env bash
set -euo pipefail

# Fail when OSV-Scanner reports HIGH or CRITICAL findings (database_specific.severity).
# Go stdlib advisories often omit severity labels; those are surfaced by govulncheck instead.

results_file="${1:?usage: check-osv-high-critical.sh <osv-results.json>}"

total="$(jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' "$results_file")"
echo "OSV-Scanner reported $total total vulnerabilities."

count="$(jq '[.results[]?.packages[]?.vulnerabilities[]?
  | select(.database_specific.severity == "HIGH" or .database_specific.severity == "CRITICAL")
] | length' "$results_file")"

if [[ "$count" -gt 0 ]]; then
  echo "OSV-Scanner found $count HIGH or CRITICAL vulnerabilities."
  jq -r '.results[]?.packages[]?.vulnerabilities[]?
    | select(.database_specific.severity == "HIGH" or .database_specific.severity == "CRITICAL")
    | "\(.database_specific.severity)\t\(.id)\t\(.summary // "no summary")"' "$results_file"
  exit 1
fi

echo "No HIGH or CRITICAL OSV findings with severity metadata."
