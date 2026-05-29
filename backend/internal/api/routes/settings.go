package routes

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/crypto"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/llm"
	"go.uber.org/zap"
)

// SettingsHandler exposes per-tenant configuration endpoints
// (GitHub App PEM and LLM credentials).
type SettingsHandler struct {
	db     *pgxpool.Pool
	encKey []byte
	log    *zap.Logger
}

func NewSettingsHandler(db *pgxpool.Pool, encKey []byte, log *zap.Logger) *SettingsHandler {
	return &SettingsHandler{db: db, encKey: encKey, log: log}
}

func (h *SettingsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/settings", authMW)
	g.GET("/github-app", h.getGitHubApp)
	g.PUT("/github-app", h.requireAdmin, h.putGitHubApp)
	g.DELETE("/github-app", h.requireAdmin, h.deleteGitHubApp)

	g.GET("/llm", h.getLLM)
	g.PUT("/llm", h.requireAdmin, h.putLLM)
	g.DELETE("/llm", h.requireAdmin, h.deleteLLM)
}

// requireAdmin gates write endpoints to owner/admin roles.
func (h *SettingsHandler) requireAdmin(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	if claims == nil || (claims.Role != "owner" && claims.Role != "admin") {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "owner or admin role required"})
		return
	}
	c.Next()
}

type githubAppStatusResponse struct {
	Configured bool       `json:"configured"`
	AppID      *int64     `json:"app_id,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

func (h *SettingsHandler) getGitHubApp(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var (
		appID     int64
		updatedAt time.Time
	)
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT app_id, updated_at
		FROM tenant_github_app_configs
		WHERE tenant_id = $1`, claims.TenantID,
	).Scan(&appID, &updatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusOK, githubAppStatusResponse{Configured: false})
		return
	}
	if err != nil {
		h.log.Error("load github app config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, githubAppStatusResponse{
		Configured: true,
		AppID:      &appID,
		UpdatedAt:  &updatedAt,
	})
}

type putGitHubAppRequest struct {
	AppID      int64  `json:"app_id" binding:"required"`
	PrivateKey string `json:"private_key" binding:"required"`
}

func (h *SettingsHandler) putGitHubApp(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req putGitHubAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pem := strings.TrimSpace(req.PrivateKey)
	if !strings.Contains(pem, "BEGIN") || !strings.Contains(pem, "PRIVATE KEY") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "private_key must be a PEM-encoded private key"})
		return
	}
	// Verify the App ID + PEM actually match by asking GitHub. This catches
	// the common mistake of putting the Installation ID in the App ID field,
	// or uploading a PEM that doesn't belong to the App ID.
	if err := githubclient.VerifyAppCredentials(c.Request.Context(), req.AppID, []byte(pem)); err != nil {
		h.log.Warn("github app verification failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "GitHub rejected this App ID + PEM combination. " +
				"Make sure the App ID matches the value shown at github.com/settings/apps/<your-app> " +
				"and the PEM was generated for that App. Details: " + err.Error(),
		})
		return
	}

	encrypted, err := crypto.Encrypt([]byte(pem), h.encKey)
	if err != nil {
		h.log.Error("encrypt PEM", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encrypt failed"})
		return
	}

	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO tenant_github_app_configs
			(tenant_id, app_id, private_key_encrypted, updated_by_user_id, updated_at, created_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			app_id = EXCLUDED.app_id,
			private_key_encrypted = EXCLUDED.private_key_encrypted,
			updated_by_user_id = EXCLUDED.updated_by_user_id,
			updated_at = NOW()`,
		claims.TenantID, req.AppID, encrypted, claims.UserID,
	)
	if err != nil {
		h.log.Error("upsert github app config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	h.log.Info("github app config updated",
		zap.String("tenant_id", claims.TenantID.String()),
		zap.String("user_id", claims.UserID.String()),
		zap.Int64("app_id", req.AppID),
	)

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SettingsHandler) deleteGitHubApp(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	result, err := h.db.Exec(c.Request.Context(),
		`DELETE FROM tenant_github_app_configs WHERE tenant_id = $1`, claims.TenantID,
	)
	if err != nil {
		h.log.Error("delete github app config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no config to delete"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---- LLM (LiteLLM / OpenAI-compatible) per-tenant config ----

type llmStatusResponse struct {
	Configured              bool       `json:"configured"`
	BaseURL                 string     `json:"base_url,omitempty"`
	Model                   string     `json:"model,omitempty"`
	HasAPIKey               bool       `json:"has_api_key"`
	TimeoutSeconds          int        `json:"timeout_seconds,omitempty"`
	AutoAnalysisMinSeverity string     `json:"auto_analysis_min_severity"`
	UpdatedAt               *time.Time `json:"updated_at,omitempty"`
}

func (h *SettingsHandler) getLLM(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	defaultMinSeverity := string(llm.DefaultAutoAnalysisMinSeverity)

	var (
		baseURL                 string
		model                   string
		apiKey                  []byte
		timeoutSeconds          int
		autoAnalysisMinSeverity string
		updatedAt               time.Time
	)
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT base_url, model, api_key_encrypted, timeout_seconds, auto_analysis_min_severity, updated_at
		FROM tenant_llm_configs
		WHERE tenant_id = $1`, claims.TenantID,
	).Scan(&baseURL, &model, &apiKey, &timeoutSeconds, &autoAnalysisMinSeverity, &updatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusOK, llmStatusResponse{
			Configured:              false,
			AutoAnalysisMinSeverity: defaultMinSeverity,
		})
		return
	}
	if err != nil {
		h.log.Error("load llm config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, llmStatusResponse{
		Configured:              true,
		BaseURL:                 baseURL,
		Model:                   model,
		HasAPIKey:               len(apiKey) > 0,
		TimeoutSeconds:          timeoutSeconds,
		AutoAnalysisMinSeverity: autoAnalysisMinSeverity,
		UpdatedAt:               &updatedAt,
	})
}

type putLLMRequest struct {
	BaseURL                 string  `json:"base_url" binding:"required"`
	Model                   string  `json:"model" binding:"required"`
	APIKey                  *string `json:"api_key"`
	TimeoutSeconds          *int    `json:"timeout_seconds"`
	AutoAnalysisMinSeverity *string `json:"auto_analysis_min_severity"`
}

func (h *SettingsHandler) putLLM(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req putLLMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	baseURL := strings.TrimSpace(req.BaseURL)
	model := strings.TrimSpace(req.Model)
	if !isHTTPURL(baseURL) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "base_url must be a valid http(s) URL"})
		return
	}
	if model == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "model must not be empty"})
		return
	}

	timeoutSeconds := 60
	if req.TimeoutSeconds != nil {
		timeoutSeconds = *req.TimeoutSeconds
	}
	if timeoutSeconds < 5 || timeoutSeconds > 600 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timeout_seconds must be between 5 and 600"})
		return
	}

	autoAnalysisMinSeverity := string(llm.DefaultAutoAnalysisMinSeverity)
	if req.AutoAnalysisMinSeverity != nil {
		parsed, err := llm.ParseAutoAnalysisMinSeverity(*req.AutoAnalysisMinSeverity)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		autoAnalysisMinSeverity = string(parsed)
	} else if existing, err := h.loadAutoAnalysisMinSeverity(c.Request.Context(), claims.TenantID); err == nil {
		autoAnalysisMinSeverity = existing
	}

	// API key handling:
	// - nil   -> preserve existing key (PATCH-style update of url/model only)
	// - ""    -> clear the stored key (fallback to anonymous / env)
	// - other -> encrypt and store
	var (
		apiKeyEncrypted []byte
		preserveKey     bool
	)
	if req.APIKey == nil {
		preserveKey = true
	} else if *req.APIKey != "" {
		enc, err := crypto.Encrypt([]byte(*req.APIKey), h.encKey)
		if err != nil {
			h.log.Error("encrypt llm api key", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "encrypt failed"})
			return
		}
		apiKeyEncrypted = enc
	}

	var query string
	var args []any
	if preserveKey {
		query = `
			INSERT INTO tenant_llm_configs
				(tenant_id, base_url, model, api_key_encrypted, timeout_seconds,
				 auto_analysis_min_severity, updated_by_user_id, updated_at, created_at)
			VALUES ($1, $2, $3, NULL, $4, $5, $6, NOW(), NOW())
			ON CONFLICT (tenant_id) DO UPDATE SET
				base_url                    = EXCLUDED.base_url,
				model                       = EXCLUDED.model,
				timeout_seconds             = EXCLUDED.timeout_seconds,
				auto_analysis_min_severity  = EXCLUDED.auto_analysis_min_severity,
				updated_by_user_id          = EXCLUDED.updated_by_user_id,
				updated_at                  = NOW()`
		args = []any{claims.TenantID, baseURL, model, timeoutSeconds, autoAnalysisMinSeverity, claims.UserID}
	} else {
		query = `
			INSERT INTO tenant_llm_configs
				(tenant_id, base_url, model, api_key_encrypted, timeout_seconds,
				 auto_analysis_min_severity, updated_by_user_id, updated_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
			ON CONFLICT (tenant_id) DO UPDATE SET
				base_url                    = EXCLUDED.base_url,
				model                       = EXCLUDED.model,
				api_key_encrypted           = EXCLUDED.api_key_encrypted,
				timeout_seconds             = EXCLUDED.timeout_seconds,
				auto_analysis_min_severity  = EXCLUDED.auto_analysis_min_severity,
				updated_by_user_id          = EXCLUDED.updated_by_user_id,
				updated_at                  = NOW()`
		args = []any{claims.TenantID, baseURL, model, apiKeyEncrypted, timeoutSeconds, autoAnalysisMinSeverity, claims.UserID}
	}

	if _, err := h.db.Exec(c.Request.Context(), query, args...); err != nil {
		h.log.Error("upsert llm config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	h.log.Info("llm config updated",
		zap.String("tenant_id", claims.TenantID.String()),
		zap.String("user_id", claims.UserID.String()),
		zap.String("model", model),
	)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SettingsHandler) deleteLLM(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	result, err := h.db.Exec(c.Request.Context(),
		`DELETE FROM tenant_llm_configs WHERE tenant_id = $1`, claims.TenantID,
	)
	if err != nil {
		h.log.Error("delete llm config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no config to delete"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SettingsHandler) loadAutoAnalysisMinSeverity(ctx context.Context, tenantID uuid.UUID) (string, error) {
	var minSeverity string
	err := h.db.QueryRow(ctx, `
		SELECT auto_analysis_min_severity
		FROM tenant_llm_configs
		WHERE tenant_id = $1`, tenantID,
	).Scan(&minSeverity)
	return minSeverity, err
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}
