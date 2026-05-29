#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

chmod +x .githooks/pre-commit .githooks/pre-push
git config core.hooksPath .githooks

echo "Git hooks installed (core.hooksPath=.githooks)."
echo "  pre-commit  -> make pre-commit   (lint, vet, typecheck, staged secrets)"
echo "  pre-push    -> make pre-push     (build, test, govulncheck)"
echo ""
echo "Optional: make security-check      (OSV, licenses, Semgrep — before opening PR)"
echo "Bypass once: git commit --no-verify / git push --no-verify"
