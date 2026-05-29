//go:build integration

package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/db"
	"go.uber.org/zap"
)

type supplyChainListResponse struct {
	Items []struct {
		ID           string `json:"id"`
		PackageName  string `json:"package_name"`
		SourceEngine string `json:"source_engine"`
	} `json:"items"`
	Total int `json:"total"`
}

func TestSupplyChainSignalsIntegration_ListSummaryDetail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	connString, err := resolveIntegrationDatabaseURL(ctx)
	if err != nil {
		t.Fatalf("resolve integration database url: %v", err)
	}
	if connString == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	_, thisFile, _, _ := runtime.Caller(0)
	migrationsPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "db", "migrations")
	if err := db.RunMigrations(connString, migrationsPath); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	tenantA := uuid.New()
	tenantB := uuid.New()
	orgA := uuid.New()
	orgB := uuid.New()
	repoA := uuid.New()
	repoB := uuid.New()
	signalAOpen := uuid.New()
	signalATriaged := uuid.New()
	signalB := uuid.New()

	if err := seedSupplyChainIntegrationData(ctx, pool, tenantA, tenantB, orgA, orgB, repoA, repoB, signalAOpen, signalATriaged, signalB); err != nil {
		t.Fatalf("seed data: %v", err)
	}

	router := gin.New()
	handler := NewSupplyChainSignalsHandler(pool, zap.NewNop())
	authMW := func(tenantID uuid.UUID) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set(middleware.ContextKeyUser, &auth.Claims{
				UserID:   uuid.New(),
				TenantID: tenantID,
				Role:     "owner",
			})
			c.Next()
		}
	}
	handler.Register(router, authMW(tenantA))

	t.Run("list respects tenant and filters", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/supply-chain-signals", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var payload supplyChainListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode list response: %v", err)
		}
		if payload.Total != 2 {
			t.Fatalf("expected total 2 for tenant A, got %d", payload.Total)
		}

		req = httptest.NewRequest(http.MethodGet, "/api/v1/supply-chain-signals?engine=guarddog", nil)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode filtered list response: %v", err)
		}
		if payload.Total != 1 {
			t.Fatalf("expected filtered total 1, got %d", payload.Total)
		}
		if len(payload.Items) != 1 || payload.Items[0].SourceEngine != "guarddog" {
			t.Fatalf("unexpected filtered items payload: %#v", payload.Items)
		}
	})

	t.Run("summary respects filters", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/supply-chain-signals/summary?engine=dataset", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var payload struct {
			Total    int              `json:"total"`
			ByEngine map[string]int64 `json:"by_engine"`
			ByStatus map[string]int64 `json:"by_status"`
			ByType   map[string]int64 `json:"by_signal_type"`
			BySev    map[string]int64 `json:"by_severity"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode summary response: %v", err)
		}
		if payload.Total != 1 {
			t.Fatalf("expected summary total 1 with engine filter, got %d", payload.Total)
		}
		if payload.ByEngine["dataset"] != 1 {
			t.Fatalf("expected by_engine.dataset = 1, got %#v", payload.ByEngine)
		}
	})

	t.Run("detail is tenant-scoped and includes evidence", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/supply-chain-signals/%s", signalB), nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for other tenant signal, got %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/supply-chain-signals/%s", signalAOpen), nil)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var payload struct {
			ID       string         `json:"id"`
			Evidence map[string]any `json:"evidence"`
			Metadata map[string]any `json:"metadata"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode detail response: %v", err)
		}
		if payload.ID != signalAOpen.String() {
			t.Fatalf("unexpected signal id: %s", payload.ID)
		}
		if payload.Evidence["source"] != "openssf-malicious-packages" {
			t.Fatalf("expected evidence source to be present, got %#v", payload.Evidence)
		}
		if payload.Metadata["source"] != "openssf-malicious-packages" {
			t.Fatalf("expected metadata source to be present, got %#v", payload.Metadata)
		}
	})
}

func seedSupplyChainIntegrationData(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantA, tenantB, orgA, orgB, repoA, repoB, signalAOpen, signalATriaged, signalB uuid.UUID,
) error {
	slugA := "tenant-a-" + tenantA.String()[:8]
	slugB := "tenant-b-" + tenantB.String()[:8]
	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, slug) VALUES
			($1, 'Tenant A', $3),
			($2, 'Tenant B', $4)
		ON CONFLICT (id) DO NOTHING;
	`, tenantA, tenantB, slugA, slugB)
	if err != nil {
		return err
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO organizations (id, tenant_id, github_org_login, scan_cron, is_active) VALUES
			($1, $2, 'org-a', '0 2 * * *', TRUE),
			($3, $4, 'org-b', '0 2 * * *', TRUE)
		ON CONFLICT (id) DO NOTHING;
	`, orgA, tenantA, orgB, tenantB)
	if err != nil {
		return err
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO repositories (id, org_id, github_repo_id, full_name, default_branch, is_archived, is_monorepo) VALUES
			($1, $2, 1001, 'org-a/repo-a', 'main', FALSE, FALSE),
			($3, $4, 1002, 'org-b/repo-b', 'main', FALSE, FALSE)
		ON CONFLICT (id) DO NOTHING;
	`, repoA, orgA, repoB, orgB)
	if err != nil {
		return err
	}

	evidence := `{"source":"openssf-malicious-packages","signal":"MAL-2026-001"}`
	metadata := `{"source":"openssf-malicious-packages","extra":"integration"}`

	_, err = pool.Exec(ctx, `
		INSERT INTO supply_chain_signals (
			id, tenant_id, repo_id, signal_type, status, severity, package_ecosystem, package_name, package_version,
			source_engine, signal_key, signal_hash, reasoning, evidence_json, metadata_json
		) VALUES
			($1, $2, $3, 'malicious_package', 'open', 'critical', 'npm', 'left-pad', '1.0.0',
			 'dataset', 'MAL-2026-001', 'hash-a-open', 'known malicious package', $7::jsonb, $8::jsonb),
			($4, $2, $3, 'suspicious_behavior', 'triaged', 'high', 'npm', 'event-stream', '3.3.6',
			 'guarddog', 'guarddog:install-script', 'hash-a-triaged', 'suspicious install script', '{}'::jsonb, '{}'::jsonb),
			($5, $6, $9, 'malicious_package', 'open', 'critical', 'npm', 'other-tenant-pkg', '0.1.0',
			 'dataset', 'MAL-2026-777', 'hash-b-open', 'other tenant data', '{}'::jsonb, '{}'::jsonb)
		ON CONFLICT (id) DO NOTHING;
	`, signalAOpen, tenantA, repoA, signalATriaged, signalB, tenantB, evidence, metadata, repoB)
	return err
}

func resolveIntegrationDatabaseURL(ctx context.Context) (string, error) {
	conn := os.Getenv("TEST_DATABASE_URL")
	if conn == "" {
		return "", nil
	}

	candidates := []string{conn}
	parsed, err := url.Parse(conn)
	if err != nil {
		return "", fmt.Errorf("parse TEST_DATABASE_URL: %w", err)
	}
	if parsed.Hostname() == "postgres" {
		local := *parsed
		if port := parsed.Port(); port != "" {
			local.Host = "localhost:" + port
		} else {
			local.Host = "localhost"
		}
		candidates = append(candidates, local.String())
	}

	for _, candidate := range candidates {
		pool, err := pgxpool.New(ctx, candidate)
		if err != nil {
			continue
		}
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		pool.Close()
		if err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not connect to TEST_DATABASE_URL using known candidates")
}
