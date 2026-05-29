# Infrastructure

## Docker Compose — development

The `docker-compose.yml` file starts 5 services:

| Service | Image | Port | Description |
|---|---|---|---|
| `postgres` | postgres:16-alpine | 5432 | Primary database |
| `redis` | redis:7-alpine | 6379 | Job queue (asynq) |
| `backend` | `./backend` (target: dev) | 8080 | Go API with Air (hot reload) |
| `worker` | `./backend` (target: dev) | — | Scan worker with Air |
| `frontend` | `./frontend` (target: dev) | 3000 | Vite dev server (HMR) |

### Hot reload

- **Backend / Worker:** [`Air`](https://github.com/air-verse/air) detects changes in `*.go` and recompiles automatically
  - API: configured in `backend/.air.toml`
  - Worker: configured in `backend/.air.worker.toml`
- **Frontend:** Native Vite HMR — changes in `*.tsx` / `*.ts` are reflected instantly

### Volumes

```yaml
postgres_data   # Postgres data (persists across restarts)
redis_data      # Redis data
go_cache        # Go module cache (avoids re-downloading)
node_modules    # node_modules isolated in the container
```

### Vite → Backend proxy

Vite (`frontend/vite.config.ts`) proxies `/auth` and `/api` to the backend:

```ts
proxy: {
  '/auth': { target: 'http://backend:8080', changeOrigin: true },
  '/api':  { target: 'http://backend:8080', changeOrigin: true },
}
```

This means the frontend accesses the backend at `http://localhost:3000/api/...` without CORS issues in dev.

## Environment variables

Copy `.env.example` to `.env` before running.

### Required in production

| Variable | Example | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://user:pass@host:5432/db?sslmode=require` | PostgreSQL connection string |
| `REDIS_URL` | `redis://:password@host:6379` | Redis URL (supports `rediss://` for TLS) |
| `JWT_SECRET` | random string ≥32 chars | JWT signing key |
| `GITHUB_CLIENT_ID` | `Iv1.xxx` | GitHub OAuth App (login) |
| `GITHUB_CLIENT_SECRET` | `xxx` | GitHub OAuth App |
| `GITHUB_REDIRECT_URL` | `https://app.example.com/auth/github/callback` | GitHub OAuth callback |
| `GOOGLE_CLIENT_ID` | `xxx.apps.googleusercontent.com` | OAuth 2.0 (optional) |
| `GOOGLE_CLIENT_SECRET` | `GOCSPX-xxx` | OAuth 2.0 (optional) |
| `GOOGLE_REDIRECT_URL` | `https://app.example.com/auth/google/callback` | Google OAuth callback |
| `GITHUB_APP_ID` | integer | GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY_PATH` | `./github-app-private-key.pem` | Path to private key |
| `GITHUB_WEBHOOK_SECRET` | random string | HMAC webhook validation |

### Optional / development

| Variable | Default | Description |
|---|---|---|
| `API_PORT` | `8080` | HTTP server port |
| `DEV_AUTH_ENABLED` | `false` | Login without SSO — **never true in production** |
| `GITHUB_SSO_ENABLED` | `true` | Enables `/auth/github` routes |
| `GOOGLE_SSO_ENABLED` | `true` | Enables `/auth/google` routes (transition) |
| `GITHUB_MEMBERSHIP_SYNC_ENABLED` | `true` | Periodic sync + manual endpoint |
| `VITE_GITHUB_SSO_ENABLED` | `true` | GitHub button on the login page |
| `VITE_GOOGLE_SSO_ENABLED` | `true` | Google button on the login page |
| `VITE_DEV_AUTH_ENABLED` | `false` | Shows dev form in the frontend |
| `VITE_API_BASE_URL` | `""` (uses Vite proxy) | API base URL for the frontend |

### Quick local development (without SSO)

```env
DATABASE_URL=postgres://devsecops:devsecops@localhost:5432/devsecops?sslmode=disable
REDIS_URL=redis://localhost:6379
JWT_SECRET=dev-secret-at-least-32-characters-here
DEV_AUTH_ENABLED=true
VITE_DEV_AUTH_ENABLED=true
GITHUB_SSO_ENABLED=false
GOOGLE_SSO_ENABLED=false
```

## Database

### Migrations

Applied automatically on `backend` startup via `golang-migrate`:

```go
// cmd/api/main.go — runs before accepting requests
db.RunMigrations(cfg.DatabaseURL, "./internal/db/migrations")
```

To run manually:
```bash
make migrate        # applies all pending migrations
make migrate-create # creates a new .up.sql / .down.sql pair
```

### Access the database in development

```bash
docker compose exec postgres psql -U devsecops -d devsecops

# Or via local psql
psql postgres://devsecops:devsecops@localhost:5432/devsecops
```

### Backup / restore in development

```bash
docker compose exec postgres pg_dump -U devsecops devsecops > backup.sql
docker compose exec -T postgres psql -U devsecops devsecops < backup.sql
```

## Multi-stage Dockerfiles

Both Dockerfiles use multi-stage builds:

```
backend/Dockerfile:
  base       → golang:1.22-alpine + git
  dev        → base + Air (hot reload) — used by docker-compose
  builder    → base + go build → binaries
  production → alpine + binaries only

frontend/Dockerfile:
  base       → node:24-alpine
  dev        → base + npm install — used by docker-compose
  builder    → base + npm ci + vite build
  production → nginx:alpine + dist/ + nginx.conf
```

For a production build:
```bash
docker build --target production -t baldr-backend ./backend
docker build --target production -t baldr-frontend ./frontend
```

## Production considerations

### Database
- Use `sslmode=require` in `DATABASE_URL`
- Enable Row-Level Security (RLS) in PostgreSQL as a second layer of multi-tenant isolation
- Configure `pgBouncer` for connection pooling in production under high load

### Redis
- Use `rediss://` (TLS) for Redis in production
- Configure a password with `AUTH`

### Server
- Set `GIN_MODE=release` to disable Gin debug logs
- The server already performs graceful shutdown on `SIGTERM` (required for Kubernetes)
- Port is configurable via `API_PORT`

### CORS
- In production, update `AllowOrigins` in `cmd/api/main.go` with the real domain
- Set `secure: true` on cookies (requires HTTPS)

### GitHub App webhook
- Set `GITHUB_WEBHOOK_SECRET` with a strong random value
- Expose `POST /webhooks/github` publicly (or use smee.io in dev)
- For local webhook development: `npx smee -u https://smee.io/xxx -t http://localhost:8080/webhooks/github`

## GitHub SSO + membership sync rollout/rollback

### Incremental rollout

1. Deploy with `GITHUB_SSO_ENABLED=true`, `GOOGLE_SSO_ENABLED=true`, `GITHUB_MEMBERSHIP_SYNC_ENABLED=true`
2. Configure the GitHub OAuth App with callback `https://<host>/auth/github/callback`
3. Validate GitHub login in staging; confirm `/auth/me` and tenant isolation
4. Run `POST /api/v1/orgs/:id/sync-memberships` and verify `org_members` / `team_members`
5. Confirm findings show `owners` after scan + sync
6. Once stable, set `GOOGLE_SSO_ENABLED=false` and `VITE_GOOGLE_SSO_ENABLED=false`

### Quick rollback

| Issue | Action |
|---|---|
| GitHub login broken | `GITHUB_SSO_ENABLED=false`, keep Google |
| Membership sync noisy | `GITHUB_MEMBERSHIP_SYNC_ENABLED=false` (scans continue) |
| Google/GitHub email mismatch | review email-based upsert linkage; user re-logs with GitHub |

Telemetry: structured logs on `membership sync completed` with counts and duration.
