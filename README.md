# Baldr

[![CI](https://github.com/purplehatlabs/Baldr/actions/workflows/ci.yml/badge.svg)](https://github.com/purplehatlabs/Baldr/actions/workflows/ci.yml)
[![Security](https://github.com/purplehatlabs/Baldr/actions/workflows/security.yml/badge.svg)](https://github.com/purplehatlabs/Baldr/actions/workflows/security.yml)

> *In Norse mythology, Baldr was slain by a single overlooked dependency — a mistletoe Frigg forgot to make harmless. Baldr the platform finds those dependencies before they find you.*

Open-source Software Composition Analysis (SCA) platform. Baldr automatically scans your GitHub organization's repositories for vulnerable and malicious dependencies, maps each finding to the responsible team via CODEOWNERS, and uses LLM analysis to help triage what actually matters.

Inspired by Snyk.io, built to be self-hosted.

---

## Features

- **SCA with OSV Scanner** — detects vulnerabilities across 30+ ecosystems (Go, npm, PyPI, Maven, Cargo, and more) using the [OSV.dev](https://osv.dev) database
- **Malicious package detection** — integrates the [OpenSSF malicious packages dataset](https://github.com/ossf/malicious-packages) and GuardDog (PyPI) for supply chain attack detection
- **LLM-powered triage** — uses a local LiteLLM proxy to analyze findings in context and generate prioritized recommendations
- **CODEOWNERS mapping** — automatically assigns each finding to the team responsible for that code path
- **Multi-tenant** — full data isolation per tenant, multiple GitHub Organizations per tenant
- **GitHub App integration** — per-tenant GitHub App with encrypted private key storage
- **GitHub SSO + Google OAuth** — login via GitHub OAuth; Google remains optional
- **Scheduled scans** — configurable cron per organization, async job queue via Redis (asynq)
- **Manual scans** — trigger from the UI or `POST /api/v1/repos/:id/scan`
- **Finding management** — suppress, mark as fixed, filter by severity / team / status
- **Risk scoring** — custom algorithm combining CVSS, reachability, and context
- **Internationalization** — English and Portuguese (pt-BR)

## Stack

| Layer | Technology |
|---|---|
| Backend API | Go 1.23 + Gin |
| Scan worker | Go + asynq (Redis) |
| Scheduler | gocron |
| Database | PostgreSQL 16 |
| Scanner | osv-scanner v2 (Go library) |
| LLM proxy | LiteLLM (OpenAI-compatible) |
| GitHub integration | GitHub App (bradleyfalzon/ghinstallation) |
| Frontend | React 18 + TypeScript + Vite |
| Async state | TanStack Query v5 |
| Styling | Tailwind CSS |
| Charts | Recharts |
| Dev environment | Docker Compose |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Docker Compose (dev)                       │
│                                                              │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │  Frontend   │   │  Backend API │   │  Worker (scan)   │  │
│  │  React/Vite │   │  Go + Gin    │   │  Go + asynq      │  │
│  │  :3000      │◄──│  :8080       │   │                  │  │
│  └─────────────┘   └──────┬───────┘   └────────┬─────────┘  │
│                           │                    │             │
│                    ┌──────▼────────────────────▼──────┐      │
│                    │           PostgreSQL :5432         │      │
│                    └───────────────────────────────────┘      │
│                    ┌───────────────────────────────────┐      │
│                    │           Redis :6379              │      │
│                    │    (job queue + scheduler)         │      │
│                    └───────────────────────────────────┘      │
│                    ┌───────────────────────────────────┐      │
│                    │       LiteLLM proxy :4000          │      │
│                    │    (OpenAI-compatible API)         │      │
│                    └───────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────┘
                           │ GitHub App
                    ┌──────▼───────┐
                    │  GitHub API  │
                    │  (repos,     │
                    │  CODEOWNERS) │
                    └──────────────┘
```

## Quick start

### Prerequisites

- Docker and Docker Compose
- (Optional) Go 1.23+ for backend development without Docker
- (Optional) Node.js 20+ for frontend development without Docker

### 1. Clone and configure

```bash
git clone https://github.com/purplehatlabs/Baldr.git
cd baldr
cp .env.example .env
```

### 2. Edit `.env`

**Always required:**
```env
# Generate with: openssl rand -base64 32
JWT_SECRET=<random-string-at-least-32-chars>
PEM_ENCRYPTION_KEY=<base64-32-bytes>
```

**For local development without SSO (fastest setup):**
```env
DEV_AUTH_ENABLED=true
VITE_DEV_AUTH_ENABLED=true
```

**For full GitHub SSO:**
```env
GITHUB_CLIENT_ID=<your-oauth-app-client-id>
GITHUB_CLIENT_SECRET=<your-oauth-app-client-secret>
GITHUB_REDIRECT_URL=http://localhost:3000/auth/github/callback
GITHUB_SSO_ENABLED=true
```

See [Configuration reference](#configuration-reference) for all variables.

### 3. Start

```bash
make dev
```

Open [http://localhost:3000](http://localhost:3000).

With `DEV_AUTH_ENABLED=true`, use the yellow "Dev login" form with any email — no OAuth needed.

## Setting up the GitHub App

All configuration is done **through the UI** — the App ID and Private Key are stored per-tenant in the database, encrypted with AES-256-GCM.

1. Create a GitHub App at `github.com/settings/apps/new` with permissions: **Contents** (read), **Metadata** (read).
2. Copy the **App ID** from the app's settings page.
3. Generate a **Private key** — a `.pem` file will be downloaded.
4. **Install** the App on your GitHub organization and note the **Installation ID** (visible in the URL after installation).
5. In Baldr: **Settings → GitHub App** → enter the App ID and upload the `.pem`.
6. In **Settings → GitHub Organizations** → connect your org with the login and Installation ID.

## Scanning repositories

On the **Repositories** page, click **"Browse GitHub"**:

- Paginated list loaded live from GitHub with infinite scroll.
- Client-side filter by name or description.
- Multi-select with checkboxes + **"Scan selected"** (up to 200 per batch).
- **"Sync all"** imports all org repos into the database without triggering scans.
- The modal caches responses for 5 minutes.

## Repository structure

```
baldr/
├── backend/
│   ├── cmd/
│   │   ├── api/            # HTTP server entrypoint
│   │   └── worker/         # Scan worker entrypoint
│   ├── internal/
│   │   ├── api/
│   │   │   ├── middleware/  # JWT auth, tenant extraction
│   │   │   └── routes/      # HTTP handlers per resource
│   │   ├── auth/            # GitHub/Google OAuth + JWT
│   │   ├── codeowners/      # CODEOWNERS file parser
│   │   ├── config/          # Environment variable loading
│   │   ├── crypto/          # AES-256-GCM encryption
│   │   ├── db/              # pgx connection pool + migrations
│   │   │   └── migrations/  # .up.sql / .down.sql files
│   │   ├── findings/        # Vulnerability analysis engine + LLM triage
│   │   ├── github/          # GitHub App client
│   │   ├── llm/             # LiteLLM integration
│   │   ├── models/          # Domain structs
│   │   ├── queue/           # asynq jobs (scan pipeline)
│   │   ├── scanner/         # OSV Scanner wrapper + manifest detector
│   │   └── scheduler/       # Per-org cron (gocron)
│   ├── go.mod
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── api/             # HTTP client functions per resource
│   │   ├── components/
│   │   │   ├── layout/      # Sidebar, Header, AppLayout
│   │   │   └── shared/      # SeverityBadge, StatusBadge, Spinner
│   │   ├── hooks/           # useAuth, useLanguage
│   │   ├── i18n/            # en + pt-BR translations
│   │   ├── lib/             # Utilities
│   │   └── pages/           # One folder per route
│   ├── package.json
│   └── Dockerfile
├── docs/                    # Detailed documentation
├── docker-compose.yml
├── .env.example
└── Makefile
```

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Health check |
| `GET` | `/auth/github` | Start GitHub OAuth flow |
| `GET` | `/auth/github/callback` | OAuth callback, issues JWT |
| `GET` | `/auth/google` | Start Google OAuth flow |
| `GET` | `/auth/google/callback` | OAuth callback, issues JWT |
| `POST` | `/auth/dev/login` | Dev login (`DEV_AUTH_ENABLED=true` only) |
| `POST` | `/auth/logout` | Clear JWT cookie |
| `GET` | `/auth/me` | Current authenticated user |
| `GET` | `/api/v1/dashboard` | Aggregated tenant metrics |
| `GET` | `/api/v1/orgs` | List GitHub orgs for tenant |
| `POST` | `/api/v1/orgs` | Connect a new GitHub org |
| `DELETE` | `/api/v1/orgs/:id` | Disconnect org |
| `GET` | `/api/v1/orgs/:id/github-repos` | List live repos from GitHub (paginated) |
| `POST` | `/api/v1/orgs/:id/github-repos/scan` | Import + scan 1 repo |
| `POST` | `/api/v1/orgs/:id/github-repos/scan-batch` | Import + scan up to 200 repos |
| `POST` | `/api/v1/orgs/:id/sync` | Import all repos without scanning |
| `GET` | `/api/v1/repos` | List tracked repositories |
| `POST` | `/api/v1/repos/:id/scan` | Trigger manual scan |
| `GET` | `/api/v1/repos/:id/jobs` | Scan job history |
| `GET` | `/api/v1/findings` | List findings (filter: severity, status, team_id) |
| `GET` | `/api/v1/findings/:id` | Finding detail |
| `PATCH` | `/api/v1/findings/:id` | Update status (open/suppressed/fixed) |
| `GET` | `/api/v1/teams` | Teams with finding counts |
| `GET` | `/api/v1/teams/:id/findings` | Open findings for a team |
| `GET` | `/api/v1/settings/github-app` | GitHub App status for tenant |
| `PUT` | `/api/v1/settings/github-app` | Upload App ID + PEM |
| `DELETE` | `/api/v1/settings/github-app` | Remove GitHub App config |
| `POST` | `/webhooks/github` | GitHub App webhook (HMAC-SHA256) |

All `/api/v1/*` endpoints require authentication via `access_token` cookie or `Authorization: Bearer <token>` header.

## Scan pipeline

```
Scheduler (cron) or manual API trigger
         │
         ▼
  Redis job queue (asynq)
         │
         ▼
  Worker receives ScanRepo job
         │
  1. Load repo + org + installation_id from DB
  2. Shallow clone (git --depth=1) with Installation Token
  3. FindManifests() → recursive scan (skips node_modules, vendor, etc.)
  4. GetCODEOWNERS() → reads CODEOWNERS / .github/CODEOWNERS / docs/CODEOWNERS
  5. For each manifest:
     a. ScanManifest() → osv-scanner v2 as Go library
     b. Persist findings
     c. OwnersForPath() → teams from CODEOWNERS
     d. Persist finding_teams
  6. Update scan_job.status + repositories.last_scanned_at
```

## Configuration reference

| Variable | Description | Required |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection string | Yes |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | Yes |
| `PEM_ENCRYPTION_KEY` | AES-256-GCM key for GitHub App PEMs, base64 (`openssl rand -base64 32`) | Yes |
| `GITHUB_CLIENT_ID` | GitHub OAuth App Client ID | For GitHub SSO |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App Client Secret | For GitHub SSO |
| `GITHUB_REDIRECT_URL` | GitHub OAuth callback URL | For GitHub SSO |
| `GITHUB_SSO_ENABLED` | `true` to enable GitHub login | No |
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID | For Google SSO |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Client Secret | For Google SSO |
| `GOOGLE_REDIRECT_URL` | Google OAuth callback URL | For Google SSO |
| `GOOGLE_SSO_ENABLED` | `true` to enable Google login | No |
| `DEV_AUTH_ENABLED` | `true` to enable local dev login (never in production) | No |
| `VITE_DEV_AUTH_ENABLED` | `true` to show dev login form in UI | No |
| `LITELLM_BASE_URL` | LiteLLM proxy URL | For LLM analysis |
| `LITELLM_MASTER_KEY` | LiteLLM API key | For LLM analysis |
| `WORKER_CONCURRENCY` | Parallel repos scanned by worker (default: 3) | No |
| `MALICIOUS_DATASET_ENABLED` | `true` to sync OpenSSF malicious packages dataset | No |
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for validating GitHub webhooks | No |
| `GITHUB_MEMBERSHIP_SYNC_ENABLED` | `true` to sync org/team members | No |

## Additional documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design decisions and detailed data flows
- [`docs/BACKEND.md`](docs/BACKEND.md) — Go conventions, handler patterns, SQL queries
- [`docs/FRONTEND.md`](docs/FRONTEND.md) — React conventions, page patterns
- [`docs/INFRASTRUCTURE.md`](docs/INFRASTRUCTURE.md) — Docker, environment variables, deployment
- [`docs/DATABASE.md`](docs/DATABASE.md) — Schema reference and query examples
- [`docs/TESTING.md`](docs/TESTING.md) — How to write and run tests

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[AGPL-3.0](LICENSE)
