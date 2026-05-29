<div align="center">

# 🛡️ Baldr

### Stop drowning in vulnerabilities. Fix the 2% that can actually hurt you.

**Open-source AppSec platform that uses an LLM agent to read your code and tell you which of your thousands of security findings are *actually reachable and exploitable* — so your team triages what matters instead of chasing CVSS scores.**

[![CI](https://github.com/purplehatlabs/Baldr/actions/workflows/ci.yml/badge.svg)](https://github.com/purplehatlabs/Baldr/actions/workflows/ci.yml)
[![Security](https://github.com/purplehatlabs/Baldr/actions/workflows/security.yml/badge.svg)](https://github.com/purplehatlabs/Baldr/actions/workflows/security.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Self-hosted](https://img.shields.io/badge/deploy-self--hosted-success.svg)](#quick-start)

[Quick start](#quick-start) · [How it works](#how-baldr-cuts-the-noise) · [Features](#features) · [Docs](#additional-documentation)

Built and maintained by **[PurpleHat Labs](https://purplehat.com.br)**.

</div>

<!--
  📸 SCREENSHOT / DEMO
  Replace the placeholder below with a real dashboard screenshot or demo GIF.
  Recommended: a wide (≈1280px) shot of the ranked findings queue, or a short GIF
  of a scan → triage flow. Drop the asset in docs/assets/ and update the path.
-->
<div align="center">

[![Baldr dashboard — ranked, explainable findings](docs/assets/dashboard.png)](docs/assets/dashboard.png)

<sub><i>The Baldr dashboard: thousands of raw findings distilled into a ranked, explainable queue.</i></sub>

</div>

> *In Norse mythology, Baldr was slain by a single overlooked dependency — a mistletoe Frigg forgot to make harmless. Baldr the platform finds those dependencies before they find you.*

---

## The problem

Point any SCA scanner at a real organization and you get **thousands of findings**. Almost all of them are noise:

- the vulnerable function is **never called** from your code,
- the package is a **transitive, build-time-only** dependency,
- the CVE is **critical on paper** but has no known exploit and isn't internet-reachable.

Security teams burn weeks manually triaging this backlog, alert fatigue sets in, and the *one* finding that's genuinely exploitable gets buried under 4,000 that aren't. Sorting by CVSS doesn't help — **severity is not risk.**

## How Baldr cuts the noise

Baldr scans your GitHub org for vulnerable and malicious dependencies like any SCA tool — and then does the part the others leave to you. For each finding, an **LLM agent explores the actual repository** to answer the question that matters: *does this vulnerability matter **here**?*

```
                        4,200 raw findings
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
   1. Reachability      2. LLM code agent    3. Risk scoring
   Is the vulnerable    Reads the repo,      Blends technical +
   symbol imported &    inspects import      threat (EPSS, CISA
   called at all?       sites, judges real   KEV) + business
                        criticality + gives  (exposure, asset
                        a confidence score   criticality)
            └──────────────────┼──────────────────┘
                               ▼
                  ~80 ranked, explainable findings
                  auto-confirmed when confidence is high,
                  each routed to the owning team
```

The result: a **ranked, explainable** queue instead of a 4,000-row CSV. High-confidence, reachable, truly-critical findings are auto-confirmed; the rest are ranked so humans review the riskiest first.

## How Baldr compares

Most tools tell you *what's vulnerable*. Baldr tells you *what to fix first* — and routes it to the right team, on infrastructure you control.

| | Dependabot | Typical SCA (Snyk, etc.) | **Baldr** |
|---|:---:|:---:|:---:|
| Multi-ecosystem SCA (OSV) | ✅ | ✅ | ✅ |
| Malicious package detection | ⚠️ limited | ✅ | ✅ |
| **Reachability analysis** | ❌ | 💲 paid tiers | ✅ |
| **LLM agent reads your code to triage** | ❌ | ❌ | ✅ |
| **Explainable risk score (EPSS + CISA KEV + business context)** | ❌ | ⚠️ partial | ✅ |
| Auto-confirm high-confidence findings | ❌ | ❌ | ✅ |
| Auto-route to owning team (CODEOWNERS) | ❌ | ⚠️ partial | ✅ |
| Org-wide scanning across many repos | ⚠️ per-repo | ✅ | ✅ |
| Bring your own LLM / data stays in your infra | n/a | ❌ | ✅ |
| Self-hosted & open source | ❌ | ❌ | ✅ (AGPL-3.0) |

<sub>Comparison reflects commonly available capabilities at time of writing; vendor offerings change. Contributions to keep this honest are welcome.</sub>

## Features

- **🤖 LLM code agent for triage** — an agent reads each affected repo (import sites, call paths, context) and produces a criticality verdict + confidence, not just a CVSS number. Reachable + truly critical + high confidence findings are **auto-confirmed**; everything else is ranked for review.
- **📊 Explainable risk scoring** — a transparent score blending three pillars: *technical* (severity, CVSS, reachability, fix availability), *threat* ([EPSS](https://www.first.org/epss/) + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)), and *business* (internet exposure, asset criticality, data sensitivity). Every score shows its factors.
- **🔍 SCA with OSV Scanner** — detects vulnerabilities across 30+ ecosystems (Go, npm, PyPI, Maven, Cargo, and more) using the [OSV.dev](https://osv.dev) database.
- **☠️ Malicious package detection** — integrates the [OpenSSF malicious packages dataset](https://github.com/ossf/malicious-packages) and GuardDog (PyPI) for supply chain attack detection.
- **👥 CODEOWNERS mapping** — automatically routes each finding to the team responsible for that code path. No more "who owns this?".
- **🏢 Multi-tenant** — full data isolation per tenant, multiple GitHub Organizations per tenant, per-tenant LLM config.
- **🔐 GitHub App integration** — per-tenant GitHub App with AES-256-GCM encrypted private key storage.
- **🔑 GitHub SSO + Google OAuth** — login via GitHub OAuth; Google remains optional.
- **⏰ Scheduled & manual scans** — configurable cron per organization with an async job queue (Redis/asynq), or trigger on demand.
- **🌐 Bring your own LLM** — talks to any OpenAI-compatible model via a local LiteLLM proxy. Your code and findings never leave your infrastructure.
- **🌍 Internationalization** — English and Portuguese (pt-BR).

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

## Maintained by

Baldr is built and maintained by **[PurpleHat Labs](https://purplehat.com.br)**.

## License

[AGPL-3.0](LICENSE)
