package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/config"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

func TestCreateManualFindingRejectsMemberRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewFindingsHandler(nil, nil, &config.Config{}, nil, zap.NewNop())
	authMW := func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
			Role:     "member",
		})
		c.Next()
	}
	handler.Register(router, authMW)

	body, _ := json.Marshal(map[string]any{
		"summary":            "Test manual finding",
		"severity":           "high",
		"external_reference": "CVE-2026-0001",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/manual", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d: %s", http.StatusForbidden, rec.Code, rec.Body.String())
	}
}

func TestCreateManualFindingRejectsInvalidPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewFindingsHandler(nil, nil, &config.Config{}, nil, zap.NewNop())
	authMW := func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
			Role:     "owner",
		})
		c.Next()
	}
	handler.Register(router, authMW)

	tests := []struct {
		name string
		body map[string]any
	}{
		{
			name: "missing summary",
			body: map[string]any{
				"severity":           "high",
				"external_reference": "CVE-2026-0001",
			},
		},
		{
			name: "missing external_reference",
			body: map[string]any{
				"summary":  "Manual finding",
				"severity": "high",
			},
		},
		{
			name: "invalid severity",
			body: map[string]any{
				"summary":            "Manual finding",
				"severity":           "urgent",
				"external_reference": "CVE-2026-0001",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/manual", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCreateManualFindingRejectsBlankRequiredFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewFindingsHandler(nil, nil, &config.Config{}, nil, zap.NewNop())
	authMW := func(c *gin.Context) {
		c.Set(middleware.ContextKeyUser, &auth.Claims{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
			Role:     "admin",
		})
		c.Next()
	}
	handler.Register(router, authMW)

	body, _ := json.Marshal(models.CreateManualFindingRequest{
		Summary:           "   ",
		Severity:          models.SeverityHigh,
		ExternalReference: " ",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/manual", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}
