//go:build integration

package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/config"
	"github.com/purplehatlabs/Baldr/internal/db"
	"go.uber.org/zap"
)

func TestManualFindingIntegration_CreateListTenantIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	connString, err := resolveManualFindingIntegrationDatabaseURL(ctx)
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
	userA := uuid.New()
	userB := uuid.New()
	memberA := uuid.New()

	if err := seedManualFindingIntegrationData(ctx, pool, tenantA, tenantB, userA, userB, memberA); err != nil {
		t.Fatalf("seed data: %v", err)
	}

	cfg := &config.Config{}
	handler := NewFindingsHandler(pool, nil, cfg, nil, zap.NewNop())

	makeRouter := func(tenantID, userID uuid.UUID, role string) *gin.Engine {
		router := gin.New()
		authMW := func(c *gin.Context) {
			c.Set(middleware.ContextKeyUser, &auth.Claims{
				UserID:   userID,
				TenantID: tenantID,
				Role:     role,
			})
			c.Next()
		}
		handler.Register(router, authMW)
		return router
	}

	ownerRouter := makeRouter(tenantA, userA, "owner")
	memberRouter := makeRouter(tenantA, memberA, "member")
	otherTenantRouter := makeRouter(tenantB, userB, "owner")

	t.Run("member forbidden", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"summary":            "Should fail",
			"severity":           "high",
			"external_reference": "CVE-2026-9999",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/manual", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		memberRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	var createdID string
	t.Run("owner creates manual finding", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"summary":            "Manual pentest finding",
			"severity":           "critical",
			"external_reference": "CVE-2026-1001",
			"external_source":    "pentest",
			"package_name":       "lodash",
			"package_version":    "4.17.20",
			"evidence":           map[string]any{"report": "Q1 pentest"},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/manual", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		ownerRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
		}
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode create response: %v", err)
		}
		if payload.ID == "" {
			t.Fatal("expected finding id")
		}
		createdID = payload.ID
	})

	t.Run("list includes manual finding with source_engine filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?source_engine=manual&status=open", nil)
		rec := httptest.NewRecorder()
		ownerRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var payload struct {
			Items []struct {
				ID           string `json:"id"`
				SourceEngine string `json:"source_engine"`
				OSVID        string `json:"osv_id"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode list response: %v", err)
		}
		if payload.Total < 1 {
			t.Fatalf("expected at least 1 manual finding, got %d", payload.Total)
		}
		found := false
		for _, item := range payload.Items {
			if item.ID == createdID {
				found = true
				if item.SourceEngine != "manual" {
					t.Fatalf("expected source_engine manual, got %s", item.SourceEngine)
				}
				if item.OSVID != "CVE-2026-1001" {
					t.Fatalf("unexpected osv_id %s", item.OSVID)
				}
			}
		}
		if !found {
			t.Fatal("created finding not found in list")
		}
	})

	t.Run("detail tenant scoped", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/findings/%s", createdID), nil)
		rec := httptest.NewRecorder()
		otherTenantRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for other tenant, got %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/findings/%s", createdID), nil)
		rec = httptest.NewRecorder()
		ownerRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("audit log manual_create", func(t *testing.T) {
		var action string
		err := pool.QueryRow(ctx, `
			SELECT action FROM finding_audit_logs
			WHERE finding_id = $1 AND tenant_id = $2
			ORDER BY created_at DESC LIMIT 1`,
			createdID, tenantA,
		).Scan(&action)
		if err != nil {
			t.Fatalf("query audit log: %v", err)
		}
		if action != "manual_create" {
			t.Fatalf("expected manual_create action, got %s", action)
		}
	})
}

func seedManualFindingIntegrationData(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantA, tenantB, userA, userB, memberA uuid.UUID,
) error {
	slugA := "mf-tenant-a-" + tenantA.String()[:8]
	slugB := "mf-tenant-b-" + tenantB.String()[:8]

	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, slug) VALUES
			($1, 'Tenant A', $3),
			($2, 'Tenant B', $4)
		ON CONFLICT (id) DO NOTHING`,
		tenantA, tenantB, slugA, slugB,
	)
	if err != nil {
		return err
	}

	devGoogleA := "dev-google-" + userA.String()
	devGoogleB := "dev-google-" + userB.String()
	devGoogleMember := "dev-google-" + memberA.String()

	_, err = pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, google_id, name, avatar_url, role) VALUES
			($1, $2, 'owner-a@example.com', $4, 'Owner A', '', 'owner'),
			($3, $5, 'owner-b@example.com', $6, 'Owner B', '', 'owner'),
			($7, $2, 'member-a@example.com', $8, 'Member A', '', 'member')
		ON CONFLICT (id) DO NOTHING`,
		userA, tenantA, userB, devGoogleA, tenantB, devGoogleB, memberA, devGoogleMember,
	)
	return err
}

func resolveManualFindingIntegrationDatabaseURL(ctx context.Context) (string, error) {
	conn := os.Getenv("TEST_DATABASE_URL")
	if conn == "" {
		return "", nil
	}
	_ = ctx
	return conn, nil
}
