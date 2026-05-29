package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"go.uber.org/zap"
)

type IntegrationsHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewIntegrationsHandler(db *pgxpool.Pool, log *zap.Logger) *IntegrationsHandler {
	return &IntegrationsHandler{db: db, log: log}
}

func (h *IntegrationsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/integrations", authMW)
	g.GET("/slack", h.getSlack)
	g.PUT("/slack", h.putSlack)
	g.DELETE("/slack", h.deleteSlack)
	g.GET("/jira", h.getJira)
	g.PUT("/jira", h.putJira)
	g.DELETE("/jira", h.deleteJira)
	g.GET("/github-checks", h.getGitHubChecks)
	g.PUT("/github-checks", h.putGitHubChecks)
	g.DELETE("/github-checks", h.deleteGitHubChecks)
}

type integrationConfigResponse struct {
	IntegrationType string         `json:"integration_type"`
	Enabled         bool           `json:"enabled"`
	Config          map[string]any `json:"config"`
	UpdatedByUserID *uuid.UUID     `json:"updated_by_user_id,omitempty"`
	UpdatedAt       *time.Time     `json:"updated_at,omitempty"`
}

type putIntegrationRequest struct {
	Enabled bool           `json:"enabled"`
	Config  map[string]any `json:"config"`
}

func (h *IntegrationsHandler) getSlack(c *gin.Context) {
	h.getConfig(c, "slack")
}

func (h *IntegrationsHandler) putSlack(c *gin.Context) {
	h.putConfig(c, "slack")
}

func (h *IntegrationsHandler) deleteSlack(c *gin.Context) {
	h.deleteConfig(c, "slack")
}

func (h *IntegrationsHandler) getJira(c *gin.Context) {
	h.getConfig(c, "jira")
}

func (h *IntegrationsHandler) putJira(c *gin.Context) {
	h.putConfig(c, "jira")
}

func (h *IntegrationsHandler) deleteJira(c *gin.Context) {
	h.deleteConfig(c, "jira")
}

func (h *IntegrationsHandler) getGitHubChecks(c *gin.Context) {
	h.getConfig(c, "github_checks")
}

func (h *IntegrationsHandler) putGitHubChecks(c *gin.Context) {
	h.putConfig(c, "github_checks")
}

func (h *IntegrationsHandler) deleteGitHubChecks(c *gin.Context) {
	h.deleteConfig(c, "github_checks")
}

func (h *IntegrationsHandler) getConfig(c *gin.Context, integrationType string) {
	claims := middleware.ClaimsFrom(c)

	var (
		enabled   bool
		configRaw []byte
		updatedBy *uuid.UUID
		updatedAt *time.Time
	)
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT is_enabled, config_json, updated_by_user_id, updated_at
		FROM integration_configs
		WHERE tenant_id = $1 AND integration_type = $2`,
		claims.TenantID, integrationType,
	).Scan(&enabled, &configRaw, &updatedBy, &updatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusOK, integrationConfigResponse{
				IntegrationType: normalizeIntegrationType(integrationType),
				Enabled:         false,
				Config:          map[string]any{},
			})
			return
		}
		h.log.Error("get integration config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	configMap := map[string]any{}
	if len(configRaw) > 0 {
		_ = json.Unmarshal(configRaw, &configMap)
	}
	c.JSON(http.StatusOK, integrationConfigResponse{
		IntegrationType: normalizeIntegrationType(integrationType),
		Enabled:         enabled,
		Config:          configMap,
		UpdatedByUserID: updatedBy,
		UpdatedAt:       updatedAt,
	})
}

func (h *IntegrationsHandler) putConfig(c *gin.Context, integrationType string) {
	claims := middleware.ClaimsFrom(c)

	var req putIntegrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Config == nil {
		req.Config = map[string]any{}
	}
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config"})
		return
	}

	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO integration_configs
			(tenant_id, integration_type, is_enabled, config_json, updated_by_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (tenant_id, integration_type) DO UPDATE SET
			is_enabled = EXCLUDED.is_enabled,
			config_json = EXCLUDED.config_json,
			updated_by_user_id = EXCLUDED.updated_by_user_id,
			updated_at = NOW()`,
		claims.TenantID, integrationType, req.Enabled, configJSON, claims.UserID,
	)
	if err != nil {
		h.log.Error("put integration config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *IntegrationsHandler) deleteConfig(c *gin.Context, integrationType string) {
	claims := middleware.ClaimsFrom(c)
	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM integration_configs
		WHERE tenant_id = $1 AND integration_type = $2`,
		claims.TenantID, integrationType,
	)
	if err != nil {
		h.log.Error("delete integration config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func normalizeIntegrationType(integrationType string) string {
	if integrationType == "github_checks" {
		return "github-checks"
	}
	return strings.ReplaceAll(integrationType, "_", "-")
}
