#!/usr/bin/env bash
set -euo pipefail

# Fail when OSV-Scanner reports HIGH or CRITICAL findings (database_specific.severity).
# Go stdlib advisories often omit severity labels; those are surfaced by govulncheck instead.

results_file="${1:?usage: check-osv-high-critical.sh <osv-results.json>}"

# Unfixed transitive Moby/docker advisories pulled in by osv-scanner container scanning.
# GHSA-x744 fixed in Moby 29.3.1, but v29.x is not yet published to the Go module proxy.
# GHSA-rg2x and GHSA-x86f have no upstream fix at the latest proxy version (28.5.2).
# Baldr does not run a Docker daemon; risk is limited to the scanner CLI dependency tree.
readonly -a OSV_ALLOWLIST=(
  GHSA-rg2x-37c3-w2rh
  GHSA-x744-4wpc-v9h2
  GHSA-x86f-5xw2-fm2r
)

allowlist_json="$(printf '%s\n' "${OSV_ALLOWLIST[@]}" | jq -R . | jq -s .)"

total="$(jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' "$results_file")"
echo "OSV-Scanner reported $total total vulnerabilities."

count="$(jq --argjson allowlist "$allowlist_json" '[.results[]?.packages[]?.vulnerabilities[]?
  | select(.database_specific.severity == "HIGH" or .database_specific.severity == "CRITICAL")
  | select(.id as $id | ($allowlist | index($id)) | not)
] | length' "$results_file")"

allowlisted_count="$(jq --argjson allowlist "$allowlist_json" '[.results[]?.packages[]?.vulnerabilities[]?
  | select(.database_specific.severity == "HIGH" or .database_specific.severity == "CRITICAL")
  | select(.id as $id | ($allowlist | index($id)))
] | length' "$results_file")"

if [[ "$allowlisted_count" -gt 0 ]]; then
  echo "Allowlisted $allowlisted_count unfixed transitive Moby/docker advisory(ies) from osv-scanner:"
  jq -r --argjson allowlist "$allowlist_json" '.results[]?.packages[]?.vulnerabilities[]?
    | select(.database_specific.severity == "HIGH" or .database_specific.severity == "CRITICAL")
    | select(.id as $id | ($allowlist | index($id)))
    | "\(.database_specific.severity)\t\(.id)\t\(.summary // "no summary")"' "$results_file"
fi

if [[ "$count" -gt 0 ]]; then
  echo "OSV-Scanner found $count HIGH or CRITICAL vulnerabilities."
  jq -r --argjson allowlist "$allowlist_json" '.results[]?.packages[]?.vulnerabilities[]?
    | select(.database_specific.severity == "HIGH" or .database_specific.severity == "CRITICAL")
    | select(.id as $id | ($allowlist | index($id)) | not)
    | "\(.database_specific.severity)\t\(.id)\t\(.summary // "no summary")"' "$results_file"
  exit 1
fi

echo "No HIGH or CRITICAL OSV findings with severity metadata."
