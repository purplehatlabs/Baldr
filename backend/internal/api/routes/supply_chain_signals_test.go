package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/auth"
)

func TestSupplyChainSignalsListRejectsInvalidFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewSupplyChainSignalsHandler(nil, nil)
	authMW := func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
		})
		c.Next()
	}
	handler.Register(router, authMW)

	tests := []struct {
		name string
		url  string
	}{
		{name: "invalid engine", url: "/api/v1/supply-chain-signals?engine=unknown"},
		{name: "invalid status", url: "/api/v1/supply-chain-signals?status=invalid"},
		{name: "invalid signal type", url: "/api/v1/supply-chain-signals?signal_type=abc"},
		{name: "invalid severity", url: "/api/v1/supply-chain-signals?severity=hot"},
		{name: "invalid repo id", url: "/api/v1/supply-chain-signals?repo_id=bad-uuid"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected %d, got %d", http.StatusBadRequest, rec.Code)
			}
		})
	}
}

func TestSupplyChainSignalsSummaryRejectsInvalidFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewSupplyChainSignalsHandler(nil, nil)
	authMW := func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
		})
		c.Next()
	}
	handler.Register(router, authMW)

	tests := []struct {
		name string
		url  string
	}{
		{name: "invalid repo id", url: "/api/v1/supply-chain-signals/summary?repo_id=bad"},
		{name: "invalid engine", url: "/api/v1/supply-chain-signals/summary?engine=unknown"},
		{name: "invalid status", url: "/api/v1/supply-chain-signals/summary?status=invalid"},
		{name: "invalid signal type", url: "/api/v1/supply-chain-signals/summary?signal_type=invalid"},
		{name: "invalid severity", url: "/api/v1/supply-chain-signals/summary?severity=invalid"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected %d, got %d", http.StatusBadRequest, rec.Code)
			}
		})
	}
}

func TestSupplyChainSignalsDetailRejectsInvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewSupplyChainSignalsHandler(nil, nil)
	authMW := func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
		})
		c.Next()
	}
	handler.Register(router, authMW)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/supply-chain-signals/not-a-uuid", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rec.Code)
	}
}
