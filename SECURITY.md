# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security problems.

Send a report to **csirt@purplehat.com.br** with:

- Description of the issue and potential impact
- Steps to reproduce or proof-of-concept
- Affected component (backend, frontend, scanner, auth)

You will receive an acknowledgement within 48 hours and a resolution timeline within 5 business days.

## Scope

This project is a self-hosted platform. The security of your deployment
(database credentials, JWT secret, GitHub App private key) is your
responsibility. See [docs/INFRASTRUCTURE.md](docs/INFRASTRUCTURE.md)
for hardening guidance.

## Disclosure Policy

We follow coordinated disclosure. We ask that you give us reasonable
time to address the issue before any public disclosure.

## CI security pipeline

Security checks run on every push and pull request to `main` via
[`.github/workflows/security.yml`](.github/workflows/security.yml):

| Job | Tool | Blocks CI |
|-----|------|-----------|
| `lint-go` | golangci-lint (incl. gosec) | Yes |
| `lint-frontend` | ESLint | Yes |
| `govulncheck` | Go vulnerability DB | Yes (fixable vulns only; see below) |
| `osv-scanner` | OSV-Scanner on `go.mod` + `package-lock.json` | Yes (HIGH/CRITICAL with severity metadata) |
| `gitleaks` | Gitleaks Action (requires org `GITLEAKS_LICENSE`) | Yes |
| `license-check` | go-licenses + license-checker | Yes |
| `semgrep` | Semgrep (`p/ci`, Go, TypeScript) | Yes |

Release tags (`v*`) additionally run in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

- **Trivy** image scan (CRITICAL/HIGH, unfixed ignored)
- **cosign** keyless (OIDC) image signing
- **Syft** SBOM generation (SPDX JSON) attached to the GitHub Release
- Docker **provenance** attestation via build-push-action

Dependabot is disabled to avoid high-volume automated PRs. Dependency risk is
monitored by the CI jobs above (`govulncheck`, `osv-scanner`, release Trivy);
upgrade dependencies manually or via focused PRs when advisories appear.

### Known exceptions

- **Gitleaks license** — organization repositories require a `GITLEAKS_LICENSE` secret (free tier available at [gitleaks.io](https://gitleaks.io)). This repository uses the org-level secret configured in GitHub Actions.
- **OSV-Scanner severity filter** — the scan step uses `continue-on-error: true` because OSV-Scanner exits non-zero when any vulnerability exists; CI failure is decided by [`.github/scripts/check-osv-high-critical.sh`](.github/scripts/check-osv-high-critical.sh), which blocks only on `database_specific.severity` of `HIGH` or `CRITICAL`. Go stdlib advisories without that field are tracked via `govulncheck` instead.
- **OSV-Scanner Go call analysis** — disabled (`--no-call-analysis=go`) because the dedicated `govulncheck` job performs Go call-graph analysis with the project toolchain.
- **Go toolchain in CI** — workflows set `GOTOOLCHAIN=auto` so `go.mod` can require a patch release (e.g. `1.26.3`) even when the runner preinstalls an older patch.
- **govulncheck unfixed transitive debt** — CI fails when `govulncheck` reports vulnerabilities with an available fix. Unfixed transitive advisories (currently Moby/docker via `osv-scanner` container scanning) are logged as warnings via [`.github/scripts/run-govulncheck.sh`](.github/scripts/run-govulncheck.sh).
- **OSV Moby/docker transitive debt (osv-scanner)** — `github.com/google/osv-scanner/v2` pulls container-scanning dependencies (`github.com/docker/docker` v28.5.2, `github.com/moby/buildkit`, `github.com/containerd/containerd`). Direct deps were upgraded where fixes exist (`pgx/v5` v5.9.2, `jwt/v5` v5.3.1, indirect `jwt/v4` v4.5.2, `go-git` v5.19.1, `go-billy` v5.9.0, `containerd` v1.7.32). Three HIGH Moby advisories remain without a resolvable Go module upgrade: `GHSA-rg2x-37c3-w2rh` and `GHSA-x86f-5xw2-fm2r` (no fix published for v28.x); `GHSA-x744-4wpc-v9h2` (fixed in Moby 29.3.1, not yet on the Go module proxy). These are allowlisted in [`.github/scripts/check-osv-high-critical.sh`](.github/scripts/check-osv-high-critical.sh) because Baldr does not embed or run a Docker daemon — only the scanner CLI dependency tree is affected. Revisit when `docker/docker` v29.x is available on proxy.golang.org or osv-scanner drops the container runtime deps.
- **go-licenses ignores** — `github.com/spdx/tools-golang` (GPL-2.0, indirect via OSV tooling) and `github.com/deitch/magic/*` (missing license metadata) are excluded until upstream metadata improves.
- **Trivy `ignore-unfixed: true`** — release image scans fail only on fixable CRITICAL/HIGH issues in base images and runtime dependencies.
- **CodeQL** — not enabled (requires GitHub Advanced Security license).

### cosign / OIDC requirements

Keyless signing needs `id-token: write` on the release job and a repository or organization that allows GitHub OIDC to Sigstore. If signing fails in a fork or restricted org, verify OIDC is enabled under repository **Settings → Actions → General**.
