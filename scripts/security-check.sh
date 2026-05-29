#!/usr/bin/env bash
# Optional local parity with .github/workflows/security.yml (non-blocking hooks).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: $1 is required. $2" >&2
    exit 1
  fi
}

echo "==> OSV-Scanner (HIGH/CRITICAL)"
require_cmd osv-scanner "Install: https://google.github.io/osv-scanner/installation/"
osv-scanner \
  --lockfile=backend/go.mod \
  --lockfile=frontend/package-lock.json \
  --no-call-analysis=go \
  --format=json \
  --output=osv-results.json
test -s osv-results.json
bash .github/scripts/check-osv-high-critical.sh osv-results.json

echo "==> Gitleaks (full history)"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --verbose
else
  echo "SKIP: gitleaks not installed (brew install gitleaks)"
fi

echo "==> Go dependency licenses"
require_cmd go-licenses "Run: go install github.com/google/go-licenses/v2@latest"
(
  cd backend
  go-licenses check ./... \
    --allowed_licenses=Apache-2.0,MIT,BSD-3-Clause,BSD-2-Clause,ISC,MPL-2.0,0BSD,CC0-1.0,Zlib,Unicode-3.0,Unlicense \
    --ignore github.com/purplehatlabs/Baldr \
    --ignore github.com/spdx/tools-golang \
    --ignore github.com/deitch/magic/pkg/magic \
    --ignore github.com/deitch/magic/pkg/magic/internal \
    --ignore github.com/deitch/magic/pkg/magic/parser
)

echo "==> npm dependency licenses"
if [[ ! -d frontend/node_modules ]]; then
  echo "Installing frontend dependencies..."
  (cd frontend && npm ci)
fi
(
  cd frontend
  npm exec --yes --package=license-checker -- license-checker \
    --production \
    --excludePrivatePackages \
    --onlyAllow "MIT;ISC;BSD-3-Clause;Apache-2.0;MIT AND ISC;0BSD;CC0-1.0"
)

echo "==> Semgrep (Go + TypeScript)"
if command -v semgrep >/dev/null 2>&1; then
  semgrep --config p/ci --config p/golang --config p/typescript --error
else
  echo "SKIP: semgrep not installed (pip install semgrep or brew install semgrep)"
fi

echo "Security checks completed."
