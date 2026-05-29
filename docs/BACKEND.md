# Backend — Development Guide (Go)

## Package structure

```
backend/
├── cmd/
│   ├── api/main.go        # HTTP server: Gin + middleware + routes
│   └── worker/main.go     # asynq worker: scan pipeline
└── internal/
    ├── api/
    │   ├── middleware/
    │   │   ├── auth.go    # Extracts JWT from cookie/header, injects claims into context
    │   │   └── rbac.go    # RequireRole / RequireAdmin authorization guards
    │   └── routes/        # One file per resource
    ├── auth/
    │   ├── google.go      # OAuth 2.0 exchange + userinfo
    │   ├── jwt.go         # Issue + Validate JWT
    │   ├── memberships.go # tenant_memberships store
    │   └── session.go     # JWT issuance from active membership role
    ├── codeowners/
    │   └── parser.go      # Parse CODEOWNERS → OwnersForPath()
    ├── config/
    │   └── config.go      # Viper env vars
    ├── db/
    │   ├── db.go          # pgxpool.New + Ping
    │   ├── migrate.go     # golang-migrate auto-run
    │   └── migrations/    # Versioned SQL
    ├── github/
    │   └── client.go      # ListOrgRepos, GetCODEOWNERS, CloneRepo
    ├── models/
    │   └── models.go      # All domain structs
    ├── queue/
    │   └── queue.go       # asynq tasks + full scan pipeline
    ├── scanner/
    │   ├── manifest.go    # FindManifests() + IsMonorepo()
    │   └── osv.go         # ScanManifest() osv-scanner wrapper
    └── scheduler/
        └── scheduler.go   # OrgScheduler (gocron per org)
```

## Adding a new endpoint

### 1. Create the handler

```go
// internal/api/routes/widgets.go
package routes

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/purplehatlabs/Baldr/internal/api/middleware"
    "go.uber.org/zap"
)

type WidgetsHandler struct {
    db  *pgxpool.Pool
    log *zap.Logger
}

func NewWidgetsHandler(db *pgxpool.Pool, log *zap.Logger) *WidgetsHandler {
    return &WidgetsHandler{db: db, log: log}
}

func (h *WidgetsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
    g := r.Group("/api/v1/widgets", authMW)
    g.GET("", h.list)
    g.POST("", h.create)
}

func (h *WidgetsHandler) list(c *gin.Context) {
    claims := middleware.ClaimsFrom(c) // ALWAYS extract tenant_id from the JWT

    rows, err := h.db.Query(c.Request.Context(), `
        SELECT id, name FROM widgets WHERE tenant_id = $1 ORDER BY name`,
        claims.TenantID, // NEVER skip this filter
    )
    // ...
    c.JSON(http.StatusOK, result)
}
```

### 2. Register in `cmd/api/main.go`

```go
routes.NewWidgetsHandler(pool, log).Register(r, authMW)
```

### 3. Golden rule: tenant isolation

```go
// CORRECT ✅
claims := middleware.ClaimsFrom(c)
h.db.Query(ctx, `SELECT ... FROM widgets WHERE tenant_id = $1`, claims.TenantID)

// WRONG ❌ — never trust tenant_id from body/query string
tenantID := c.Query("tenant_id") // NEVER
```

## Multi-tenant auth and RBAC

- `GET /auth/tenants` — lists active memberships for the signed-in user.
- `POST /auth/switch-tenant` — body `{ "tenant_id": "<uuid>" }`; validates membership and reissues JWT cookie with role + `token_version`.
- `GET /api/v1/members` — list tenant members (admin/owner only).
- `PATCH /api/v1/members/:id` — update role or status (admin/owner only); bumps `tenant_memberships.token_version` to invalidate existing JWTs for that user in the tenant.
- `POST /api/v1/invites` — create email invite (admin/owner only).
- `GET /api/v1/invites` — list pending invites (admin/owner only).
- `DELETE /api/v1/invites/:id` — revoke pending invite (admin/owner only).
- `POST /api/v1/invites/:token/accept` — accept invite for the signed-in user (email must match).
- JWT claims include `token_version`; `middleware.Auth(tokens, memberships)` rejects stale sessions with `401 session expired`.
- `users.tenant_id` and `users.role` are **deprecated** — handlers read role/tenant from JWT + `tenant_memberships`; legacy columns remain for bootstrap/backfill only.
- First user bootstrap on new tenant creation assigns `admin` in `tenant_memberships`.
- Use `middleware.RequireAdmin()` or `middleware.RequireRole(...)` on routes that need elevated access.

Integration tests (`//go:build integration`) live in `internal/api/routes/auth_tenant_security_integration_test.go` and require `TEST_DATABASE_URL`. CI runs them against a PostgreSQL service container.

## SQL queries

We use `pgx/v5` directly — no ORM, no sqlc. Patterns:

```go
// Query returning multiple rows
rows, err := h.db.Query(ctx, `SELECT id, name FROM table WHERE tenant_id = $1`, tenantID)
if err != nil { ... }
defer rows.Close()
for rows.Next() {
    var row MyStruct
    if err := rows.Scan(&row.ID, &row.Name); err != nil { continue }
    results = append(results, row)
}

// Query returning a single row
var obj MyStruct
err := h.db.QueryRow(ctx, `SELECT ... WHERE id = $1`, id).Scan(&obj.ID, ...)
// err == pgx.ErrNoRows when not found

// Exec (INSERT/UPDATE/DELETE)
result, err := h.db.Exec(ctx, `UPDATE ... WHERE id = $1 AND tenant_id = $2`, id, tenantID)
if result.RowsAffected() == 0 { /* not found */ }

// Transaction
tx, err := h.db.Begin(ctx)
defer tx.Rollback(ctx) // no-op if already committed
// ... queries with tx.Exec / tx.QueryRow
tx.Commit(ctx)
```

## Migrations

Always create a `.up.sql` + `.down.sql` pair:

```bash
# Naming convention: NNNNNN_description_in_snake_case.up.sql
backend/internal/db/migrations/
  000001_init_schema.up.sql
  000001_init_schema.down.sql
  000002_add_widgets_table.up.sql   ← next migration
  000002_add_widgets_table.down.sql
```

Rules:
- **Never modify** an already-committed migration — create a new migration instead
- Every new table must have `tenant_id uuid NOT NULL REFERENCES tenants(id)`
- PKs are always `uuid DEFAULT gen_random_uuid()`
- Timestamps are always `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
- Create indexes for all foreign keys and columns used in frequent filters

```sql
-- Template for a new table
CREATE TABLE widgets (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_widgets_tenant_id ON widgets(tenant_id);
```

## Domain models

All structs live in `internal/models/models.go`. Use `json` and `db` tags on every field:

```go
type Widget struct {
    ID        uuid.UUID `json:"id" db:"id"`
    TenantID  uuid.UUID `json:"tenant_id" db:"tenant_id"`
    Name      string    `json:"name" db:"name"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
}
```

## Async jobs (asynq)

For long-running operations, always use the queue instead of processing in-request:

```go
// Define the type and payload in internal/queue/queue.go
const TaskMyJob = "myjob:do"

type MyJobPayload struct {
    ResourceID string `json:"resource_id"`
}

func NewMyJobTask(resourceID string) (*asynq.Task, error) {
    payload, _ := json.Marshal(MyJobPayload{ResourceID: resourceID})
    return asynq.NewTask(TaskMyJob, payload, asynq.Queue(QueueDefault)), nil
}

// Register handler in RegisterHandlers()
mux.HandleFunc(TaskMyJob, h.HandleMyJob)

// Enqueue from the HTTP handler
task, _ := queue.NewMyJobTask(resourceID)
client.Enqueue(task)
```

## Logging

Use structured `zap` — no `fmt.Println` or `log.Printf`:

```go
// Inject the logger into the handler via constructor
h.log.Info("operation completed", zap.String("id", id), zap.Int("count", n))
h.log.Error("operation failed", zap.Error(err), zap.String("repo", fullName))
h.log.Warn("warning", zap.String("reason", "something suspicious"))
```

## Tests

Conventions:

- **Unit:** `_test.go` in the same package, no database, mock external dependencies
- **Integration:** `_integration_test.go`, spin up PostgreSQL via `testcontainers-go`
- **Naming:** `TestFunctionName_Scenario` (e.g. `TestScanManifest_GoMod`)
- Run with `go test ./...` or `make test`

```go
// Example unit test for the CODEOWNERS parser
func TestOwnersForPath_TeamMatch(t *testing.T) {
    rs, err := codeowners.Parse("services/auth/ @acme/platform\n")
    require.NoError(t, err)
    owners := rs.OwnersForPath("services/auth/go.mod")
    require.Len(t, owners, 1)
    assert.Equal(t, "platform", owners[0].TeamSlug)
}
```
