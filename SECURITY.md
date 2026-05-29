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
| `gitleaks` | Gitleaks CLI (`gitleaks detect`) | Yes |
| `license-check` | go-licenses + license-checker | Yes |
| `semgrep` | Semgrep (`p/ci`, Go, TypeScript) | Yes |

Release tags (`v*`) additionally run in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

- **Trivy** image scan (CRITICAL/HIGH, unfixed ignored)
- **cosign** keyless (OIDC) image signing
- **Syft** SBOM generation (SPDX JSON) attached to the GitHub Release
- Docker **provenance** attestation via build-push-action

Dependency updates are proposed weekly by
[Dependabot](.github/dependabot.yml) for Go modules, npm, and GitHub Actions.

### Known exceptions

- **Gitleaks license** — organization repositories require a `GITLEAKS_LICENSE` secret (free tier available at [gitleaks.io](https://gitleaks.io)). This repository uses the org-level secret configured in GitHub Actions.
- **OSV-Scanner severity filter** — only advisories with `database_specific.severity` of `HIGH` or `CRITICAL` fail CI. Go stdlib advisories without that field are tracked via `govulncheck` instead.
- **govulncheck unfixed transitive debt** — CI fails when `govulncheck` reports vulnerabilities with an available fix. Unfixed transitive advisories (currently Moby/docker via `osv-scanner` container scanning) are logged as warnings via [`.github/scripts/run-govulncheck.sh`](.github/scripts/run-govulncheck.sh).
- **Gitleaks** — uses the open-source CLI from GitHub releases (no `gitleaks-action` license).
- **go-licenses ignores** — `github.com/spdx/tools-golang` (GPL-2.0, indirect via OSV tooling) and `github.com/deitch/magic/*` (missing license metadata) are excluded until upstream metadata improves.
- **Trivy `ignore-unfixed: true`** — release image scans fail only on fixable CRITICAL/HIGH issues in base images and runtime dependencies.
- **CodeQL** — not enabled (requires GitHub Advanced Security license).

### cosign / OIDC requirements

Keyless signing needs `id-token: write` on the release job and a repository or organization that allows GitHub OIDC to Sigstore. If signing fails in a fork or restricted org, verify OIDC is enabled under repository **Settings → Actions → General**.
