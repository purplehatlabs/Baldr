# Testing

## Strategy

| Layer | Framework | Location | When to run |
|---|---|---|---|
| Go — unit | `testing` + `testify` | `*_test.go` next to the package | `go test ./...` |
| Go — integration | `testing` + `testcontainers-go` | `*_integration_test.go` | `go test -tags integration ./...` |
| Frontend — unit | Vitest + @testing-library/react | `*.test.tsx` next to the component | `npm test` |
| Frontend — E2E | Playwright (future) | `e2e/` | CI only |

## Backend — unit tests

### Run

```bash
cd backend
go test ./...                          # all unit tests
go test ./internal/auth/...            # GitHub provider + user store helpers
go test ./internal/membership/...      # membership sync helpers
go test ./internal/api/routes/...      # auth route helpers
go test -run TestScanManifest_GoMod .  # specific test
go test -v ./...                       # verbose
go test -cover ./...                   # coverage
```

### Test structure

```go
// internal/codeowners/parser_test.go
package codeowners_test

import (
    "testing"
    "github.com/purplehatlabs/Baldr/internal/codeowners"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestOwnersForPath_TeamMatch(t *testing.T) {
    content := "services/auth/ @acme/platform\n*.go @acme/backend\n"
    rs, err := codeowners.Parse(content)
    require.NoError(t, err)

    owners := rs.OwnersForPath("services/auth/go.mod")
    require.Len(t, owners, 1)
    assert.True(t, owners[0].IsTeam)
    assert.Equal(t, "platform", owners[0].TeamSlug)
}

func TestOwnersForPath_NoMatch(t *testing.T) {
    rs, _ := codeowners.Parse("docs/ @acme/docs\n")
    owners := rs.OwnersForPath("src/main.go")
    assert.Empty(t, owners)
}
```

### Scanner tests (unit with temp file)

```go
// internal/scanner/manifest_test.go
func TestFindManifests_Monorepo(t *testing.T) {
    dir := t.TempDir()
    os.MkdirAll(filepath.Join(dir, "services/auth"), 0755)
    os.WriteFile(filepath.Join(dir, "services/auth/go.mod"), []byte("module auth\n"), 0644)
    os.MkdirAll(filepath.Join(dir, "frontend"), 0755)
    os.WriteFile(filepath.Join(dir, "frontend/package-lock.json"), []byte("{}"), 0644)

    manifests, err := scanner.FindManifests(dir)
    require.NoError(t, err)
    assert.Len(t, manifests, 2)
    assert.True(t, scanner.IsMonorepo(manifests))
}
```

### HTTP handler tests (no database)

```go
// internal/api/routes/health_test.go
func TestHealthCheck(t *testing.T) {
    r := gin.New()
    routes.RegisterHealth(r)

    w := httptest.NewRecorder()
    req := httptest.NewRequest("GET", "/healthz", nil)
    r.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
    assert.Contains(t, w.Body.String(), `"status":"ok"`)
}
```

## Backend — integration tests

> Require a running PostgreSQL accessible via `TEST_DATABASE_URL`.

```go
//go:build integration

// internal/api/routes/findings_integration_test.go
package routes_test

import (
    "context"
    "testing"
    "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestMain(m *testing.M) {
    ctx := context.Background()
    pgContainer, _ := postgres.Run(ctx, "postgres:16-alpine",
        postgres.WithDatabase("testdb"),
        postgres.WithUsername("test"),
        postgres.WithPassword("test"),
    )
    defer pgContainer.Terminate(ctx)
    // run migrations, populate fixtures
    os.Exit(m.Run())
}
```

Run:
```bash
TEST_DATABASE_URL=postgres://devsecops:devsecops@localhost:5432/devsecops?sslmode=disable \
go test -tags integration -count=1 ./...
```

## Frontend — unit tests

### Run

```bash
cd frontend
npm test              # watch mode (Vitest)
npm run test -- --run # single run (CI)
```

### Component test structure

```tsx
// src/components/shared/SeverityBadge.test.tsx
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { SeverityBadge } from './SeverityBadge'

describe('SeverityBadge', () => {
  it('displays Critical label for severity critical', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('applies red colour class for critical', () => {
    const { container } = render(<SeverityBadge severity="critical" />)
    expect(container.firstChild).toHaveClass('bg-red-100')
  })
})
```

### Testing hooks with TanStack Query

```tsx
// src/hooks/useAuth.test.ts
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import { useAuth } from './useAuth'
import * as authApi from '@/api/auth'

vi.mock('@/api/auth')

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={new QueryClient()}>
    {children}
  </QueryClientProvider>
)

it('returns user when authenticated', async () => {
  vi.mocked(authApi.getMe).mockResolvedValue({
    id: '123', email: 'test@test.com', name: 'Test', role: 'owner',
    tenant_id: 'tenant-1', avatar_url: '', created_at: ''
  })

  const { result } = renderHook(() => useAuth(), { wrapper })
  await waitFor(() => expect(result.current.isAuthenticated).toBe(true))
  expect(result.current.user?.email).toBe('test@test.com')
})
```

### Mocking the API client

```ts
// Mock entire module
vi.mock('@/api/findings')
import * as findingsApi from '@/api/findings'
vi.mocked(findingsApi.listFindings).mockResolvedValue([])

// Mock an error
vi.mocked(findingsApi.listFindings).mockRejectedValue(new Error('Network error'))
```

## CI — recommended execution order

```bash
# 1. Backend
cd backend
go build ./...             # ensures it compiles
go vet ./...               # static lint
go test ./...              # unit tests

# 2. Frontend
cd frontend
node_modules/.bin/tsc --noEmit    # type check
npm run lint                       # eslint
npm run test -- --run              # unit tests

# 3. Integration (in an environment with Docker)
cd backend
go test -tags integration -count=1 ./...
```

## Local git hooks

Install once to mirror CI before commit/push:

```bash
make install-hooks
```

| Hook | Make target | What it runs | ~Time |
|---|---|---|---|
| `pre-commit` | `make pre-commit` | `go vet`, `golangci-lint`, ESLint, `tsc`, gitleaks (staged) | 20–60s |
| `pre-push` | `make pre-push` | `go build`, `go test`, `govulncheck`, `tsc`, Vitest | 1–3 min |

Run manually anytime:

```bash
make pre-commit    # fast lint/typecheck
make pre-push      # full CI unit-test parity
make security-check  # optional: OSV, licenses, Semgrep (security.yml)
```

**Prerequisites:** Go 1.26.3 (`GOTOOLCHAIN=auto`), `golangci-lint` v2.11.4, `cd frontend && npm ci`, and optionally [gitleaks](https://github.com/gitleaks/gitleaks) for staged secret scanning (free CLI — no license needed locally).

**Bypass once:** `git commit --no-verify` or `git push --no-verify` when you intentionally skip hooks.

Docker image scans (Trivy) and release signing run only on version tags in CI — not included in local hooks.

## Fixtures and test data

For tests that need data in the database, create SQL fixtures:

```
backend/internal/db/fixtures/
  test_tenant.sql
  test_user.sql
  test_org.sql
```

```sql
-- test_tenant.sql
INSERT INTO tenants (id, name, slug) VALUES
  ('00000000-0000-0000-0000-000000000001', 'Test Tenant', 'test-tenant');
```

Load in integration tests:
```go
pool.Exec(ctx, readFile("../db/fixtures/test_tenant.sql"))
```
