# Architecture

## Overview

The platform consists of two independent Go processes (API, Worker) and a React frontend, all orchestrated via Docker Compose in development.

## Design decisions

### Multi-tenancy

**Strategy:** Row-level isolation with `tenant_id` on all tables.

- `tenant_id` is extracted from the JWT in middleware — never from the request body
- Every query that accesses user data filters by `tenant_id`
- A tenant is automatically created on first login (GitHub, Google, or dev)
- Future: add PostgreSQL RLS as a second layer of defence

```go
// Required pattern in all protected handlers
claims := middleware.ClaimsFrom(c)
// use claims.TenantID in every query
```

### Authentication

**GitHub OAuth flow (primary):**
```
Browser → GET /auth/github → GitHub consent
GitHub  → GET /auth/github/callback?code=xxx&state=yyy
Backend → exchanges code for token → fetches /user (+ /user/emails if needed)
Backend → upsert by github_user_id (fallback link by email) → issues JWT (24h)
Frontend → JWT in httpOnly cookie → sent automatically
```

**Google OAuth flow (optional, transition):**
```
Browser → GET /auth/google → Google consent
Google  → GET /auth/google/callback?code=xxx&state=yyy
Backend → exchanges code for token → fetches userinfo
Backend → upserts user in DB → issues JWT (24h)
```

Feature flags: `GITHUB_SSO_ENABLED`, `GOOGLE_SSO_ENABLED`. Rollback: disable GitHub and keep Google.

**Membership sync (GitHub App):**
```
Scheduler (04:00 UTC) or POST /api/v1/orgs/:id/sync-memberships
  → lists org members + members per team slug
  → upsert org_members + team_members (idempotent)
  → links org_members.user_id when user has logged in via GitHub SSO
Findings API resolves finding → teams → team_members → org_members → users
```

**JWT payload:**
```json
{ "user_id": "uuid", "tenant_id": "uuid", "email": "...", "role": "owner|admin|member" }
```

**Dev auth** (`DEV_AUTH_ENABLED=true` only):
```
POST /auth/dev/login { email, name }
→ upsert user (google_id = "dev:<uuid>")
→ issues same JWT
```

### Scan pipeline

The scan is processed asynchronously so it does not block the API:

```
API (manual trigger or webhook)
    ↓
asynq.Client.Enqueue(TaskScanRepo)
    ↓
Redis queue "scan" (priority 10)
    ↓
Worker.Handle() — up to 5 concurrent
    ↓
1. pgx: load repo + org + installation_id
2. ghinstallation: Installation Access Token (expires in 1h)
3. git clone --depth=1 (shallow, saves bandwidth)
4. scanner.FindManifests() — recursive WalkDir
5. codeowners.Parse(content) — hmarr/codeowners
6. For each manifest:
   osvscanner.DoScan() → models.VulnerabilityResults
   mapResults() → []models.Finding
   upsertFinding() — ON CONFLICT DO NOTHING (idempotent)
   OwnersForPath() → upsertTeam() + finding_teams
7. UPDATE scan_job status='completed'
8. os.RemoveAll(cloneDir) — cleanup guaranteed by defer
```

### Monorepo detection

`scanner.FindManifests()` recursively walks the cloned repository. If manifests are found in more than one distinct directory, `repositories.is_monorepo` is set to `true`. The scanner creates a separate `manifest` per path, making it possible to track which service each vulnerability came from.

### CODEOWNERS → teams mapping

1. Looks for `CODEOWNERS` in three standard GitHub locations
2. For each `manifest.path`, calls `Ruleset.OwnersForPath(path)`
3. Filters only `@org/team-slug` entries (ignores individual `@username`)
4. Upserts into `teams` (idempotent by `org_id + github_team_slug`)
5. Inserts into `finding_teams` with `ON CONFLICT DO NOTHING`

### Scheduler

`OrgScheduler` uses `gocron` to register one cron job per active organization:

```go
// On worker/api startup:
sched.Start(ctx)  // loads crons from DB immediately
// Every 5 minutes: re-syncs (picks up new orgs / changed crons)
```

Each cron job enqueues a `TaskScanRepo` for every non-archived repository in the org.

## Full data flow

```
[GitHub Org] ──── webhook push ────► POST /webhooks/github
                                              │
[UI / API client] ──── manual ──────► POST /api/v1/repos/:id/scan
                                              │
[gocron scheduler] ── cron ─────────────────►│
                                              ▼
                                     asynq: queue "scan"
                                              │
                                              ▼
                                     Worker.Handle()
                                              │
                          ┌───────────────────┼───────────────────┐
                          ▼                   ▼                   ▼
                    GitHub API          OSV Scanner           CODEOWNERS
                    (clone repo)     (scan manifests)        (map owners)
                          │                   │                   │
                          └───────────────────┼───────────────────┘
                                              ▼
                                       PostgreSQL
                                   (findings, teams,
                                   finding_teams, scan_jobs)
                                              │
                                              ▼
                                    React Dashboard
                                  (findings, teams, metrics)
```

## Key dependencies and rationale

| Package | Reason |
|---|---|
| `gin-gonic/gin` | Mature HTTP framework, easy middleware, JSON binding |
| `jackc/pgx/v5` | Native Go PostgreSQL driver, efficient pooling, no ORM |
| `golang-migrate/migrate` | Versioned migrations applied automatically on startup |
| `golang-jwt/jwt/v5` | Simple JWT, no extra dependencies |
| `bradleyfalzon/ghinstallation/v2` | GitHub App JWT → Installation Access Token |
| `google/go-github/v63` | Typed GitHub REST API client |
| `google/osv-scanner/v2` | Official OSV library, supports 30+ ecosystems |
| `hmarr/codeowners` | Battle-tested CODEOWNERS parser, native Go |
| `hibiken/asynq` | Simple and reliable Redis job queue with built-in web UI |
| `go-co-op/gocron/v2` | Go cron scheduler with a clean API |
| `spf13/viper` | Config via env vars + .env file |
| `go.uber.org/zap` | High-performance structured logger |

## Security

- JWT tokens in **httpOnly cookies** (not accessible by JS)
- CSRF: random state in OAuth flow (short-lived cookie)
- GitHub webhooks validated with **HMAC-SHA256**
- Installation Tokens generated on demand (expire in 1h, not persisted)
- Git clone uses ephemeral token, masked in logs
- `DEV_AUTH_ENABLED` disables mandatory Google OAuth **and** exposes an insecure endpoint — never `true` in production
