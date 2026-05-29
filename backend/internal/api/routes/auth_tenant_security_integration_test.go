//go:build integration

package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

func TestTenantSecurity_CrossTenantAccessDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	connString, err := resolveIntegrationDatabaseURL(ctx)
	if err != nil || connString == "" {
		t.Skip("TEST_DATABASE_URL not available; skipping integration test")
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
	orgA := uuid.New()
	orgB := uuid.New()

	if err := seedTenantSecurityData(ctx, pool, tenantA, tenantB, userA, userB, orgA, orgB); err != nil {
		t.Fatalf("seed: %v", err)
	}

	dashboard := NewDashboardHandler(pool, zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:       userA,
			TenantID:     tenantA,
			Email:        "user-a@test.local",
			Role:         string(models.RoleAdmin),
			TokenVersion: 1,
		})
		c.Next()
	})
	dashboard.Register(router, func(c *gin.Context) { c.Next() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status %d: %s", rec.Code, rec.Body.String())
	}

	orgsHandler := NewOrgsHandler(pool, nil, nil, nil, false, zap.NewNop())
	orgsRouter := gin.New()
	orgsRouter.Use(func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:       userA,
			TenantID:     tenantA,
			Role:         string(models.RoleAdmin),
			TokenVersion: 1,
		})
		c.Next()
	})
	orgsHandler.Register(orgsRouter, func(c *gin.Context) { c.Next() })

	reqOrgB := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/"+orgB.String(), nil)
	recOrgB := httptest.NewRecorder()
	orgsRouter.ServeHTTP(recOrgB, reqOrgB)
	if recOrgB.Code != http.StatusNotFound && recOrgB.Code != http.StatusForbidden {
		t.Fatalf("expected 404 or 403 for cross-tenant org, got %d: %s", recOrgB.Code, recOrgB.Body.String())
	}
}

func TestTenantSecurity_SwitchTenantReissuesRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	connString, err := resolveIntegrationDatabaseURL(ctx)
	if err != nil || connString == "" {
		t.Skip("TEST_DATABASE_URL not available; skipping integration test")
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

	userID := uuid.New()
	tenantA := uuid.New()
	tenantB := uuid.New()

	if err := seedMultiTenantUser(ctx, pool, userID, tenantA, tenantB); err != nil {
		t.Fatalf("seed multi tenant: %v", err)
	}

	secret := "test-jwt-secret-at-least-32-chars-long"
	tokens := auth.NewTokenService(secret)
	memberships := auth.NewMembershipStore(pool)
	handler := NewAuthHandler(AuthHandlerConfig{
		Tokens: tokens,
		DB:     pool,
		Log:    zap.NewNop(),
	})

	router := gin.New()
	tokenAdmin, err := tokens.Issue(userID, tenantA, "multi@test.local", string(models.RoleAdmin), 1)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	router.Use(middleware.Auth(tokens, memberships))
	handler.RegisterProtected(router, func(c *gin.Context) { c.Next() })

	body, _ := json.Marshal(map[string]string{"tenant_id": tenantB.String()})
	req := httptest.NewRequest(http.MethodPost, "/auth/switch-tenant", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tokenAdmin})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("switch tenant status %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode switch response: %v", err)
	}
	if resp.Role != string(models.RoleMember) {
		t.Fatalf("expected member role in tenant B, got %s", resp.Role)
	}
}

func TestTenantSecurity_MembersCrossTenantUpdateDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	connString, err := resolveIntegrationDatabaseURL(ctx)
	if err != nil || connString == "" {
		t.Skip("TEST_DATABASE_URL not available; skipping integration test")
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
	orgA := uuid.New()
	orgB := uuid.New()

	if err := seedTenantSecurityData(ctx, pool, tenantA, tenantB, userA, userB, orgA, orgB); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var membershipB uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT id FROM tenant_memberships WHERE tenant_id = $1 AND user_id = $2`,
		tenantB, userB,
	).Scan(&membershipB); err != nil {
		t.Fatalf("lookup tenant B membership: %v", err)
	}

	secret := "test-jwt-secret-at-least-32-chars-long"
	tokens := auth.NewTokenService(secret)
	memberships := auth.NewMembershipStore(pool)
	handler := NewMembersHandler(pool, zap.NewNop())

	router := gin.New()
	tokenA, err := tokens.Issue(userA, tenantA, "user-a@test.local", string(models.RoleAdmin), 1)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	router.Use(middleware.Auth(tokens, memberships))
	handler.Register(router, func(c *gin.Context) { c.Next() })

	body, _ := json.Marshal(map[string]string{"role": string(models.RoleMember)})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/members/"+membershipB.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tokenA})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-tenant member update, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTenantSecurity_StaleTokenAfterRoleChange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	connString, err := resolveIntegrationDatabaseURL(ctx)
	if err != nil || connString == "" {
		t.Skip("TEST_DATABASE_URL not available; skipping integration test")
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
	orgA := uuid.New()
	orgB := uuid.New()

	if err := seedTenantSecurityData(ctx, pool, tenantA, tenantB, userA, userB, orgA, orgB); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var membershipA uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT id FROM tenant_memberships WHERE tenant_id = $1 AND user_id = $2`,
		tenantA, userA,
	).Scan(&membershipA); err != nil {
		t.Fatalf("lookup membership: %v", err)
	}

	secret := "test-jwt-secret-at-least-32-chars-long"
	tokens := auth.NewTokenService(secret)
	memberships := auth.NewMembershipStore(pool)
	staleToken, err := tokens.Issue(userA, tenantA, "user-a@test.local", string(models.RoleAdmin), 1)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	newRole := models.RoleMember
	if _, err := memberships.UpdateMember(ctx, tenantA, membershipA, &newRole, nil); err != nil {
		t.Fatalf("update member role: %v", err)
	}

	handler := NewMembersHandler(pool, zap.NewNop())
	router := gin.New()
	router.Use(middleware.Auth(tokens, memberships))
	handler.Register(router, func(c *gin.Context) { c.Next() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/members", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: staleToken})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func seedTenantSecurityData(ctx context.Context, pool *pgxpool.Pool, tenantA, tenantB, userA, userB, orgA, orgB uuid.UUID) error {
	now := time.Now()
	for _, spec := range []struct {
		tenantID, userID, orgID uuid.UUID
		email, slug            string
		role                   models.UserRole
		orgLogin               string
	}{
		{tenantA, userA, orgA, "user-a@test.local", "tenant-a", models.RoleAdmin, "org-a"},
		{tenantB, userB, orgB, "user-b@test.local", "tenant-b", models.RoleAdmin, "org-b"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenants (id, name, slug, created_at) VALUES ($1, $2, $3, $4)`,
			spec.tenantID, spec.slug, spec.slug, now,
		); err != nil {
			return err
		}
		devGoogleID := "dev:" + spec.userID.String()
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (id, tenant_id, email, google_id, name, avatar_url, role, auth_provider, created_at)
			VALUES ($1, $2, $3, $4, $5, '', $6, 'dev', $7)`,
			spec.userID, spec.tenantID, spec.email, devGoogleID, spec.email, spec.role, now,
		); err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_memberships (tenant_id, user_id, role, status, token_version, created_at, updated_at)
			VALUES ($1, $2, $3, 'active', 1, $4, $4)`,
			spec.tenantID, spec.userID, spec.role, now,
		); err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, tenant_id, github_org_login, created_at)
			VALUES ($1, $2, $3, $4)`,
			spec.orgID, spec.tenantID, spec.orgLogin, now,
		); err != nil {
			return err
		}
	}
	return nil
}

func seedMultiTenantUser(ctx context.Context, pool *pgxpool.Pool, userID, tenantA, tenantB uuid.UUID) error {
	now := time.Now()
	email := "multi@test.local"
	devGoogleID := "dev:" + userID.String()

	for _, spec := range []struct {
		tenantID uuid.UUID
		slug     string
		role     models.UserRole
	}{
		{tenantA, "multi-a", models.RoleAdmin},
		{tenantB, "multi-b", models.RoleMember},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO tenants (id, name, slug, created_at) VALUES ($1, $2, $3, $4)`,
			spec.tenantID, spec.slug, spec.slug, now,
		); err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_memberships (tenant_id, user_id, role, status, token_version, created_at, updated_at)
			VALUES ($1, $2, $3, 'active', 1, $4, $4)`,
			spec.tenantID, userID, spec.role, now,
		); err != nil {
			return err
		}
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, google_id, name, avatar_url, role, auth_provider, created_at)
		VALUES ($1, $2, $3, $4, $5, '', $6, 'dev', $7)`,
		userID, tenantA, email, devGoogleID, email, models.RoleAdmin, now,
	)
	return err
}
