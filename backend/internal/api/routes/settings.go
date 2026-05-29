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
	g.PUT("/github-app", middleware.RequireAdmin(), h.putGitHubApp)
	g.DELETE("/github-app", middleware.RequireAdmin(), h.deleteGitHubApp)

	g.GET("/llm", h.getLLM)
	g.PUT("/llm", middleware.RequireAdmin(), h.putLLM)
	g.DELETE("/llm", middleware.RequireAdmin(), h.deleteLLM)
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
	DefaultModel            string     `json:"default_model,omitempty"`
	AgenticModel            string     `json:"agentic_model,omitempty"`
	TranslationModel        string     `json:"translation_model,omitempty"`
	BatchEnabled            bool       `json:"batch_enabled"`
	BatchMode               string     `json:"batch_mode,omitempty"`
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
		defaultModel            string
		agenticModel            string
		translationModel        string
		batchEnabled            bool
		batchMode               string
		apiKey                  []byte
		timeoutSeconds          int
		autoAnalysisMinSeverity string
		updatedAt               time.Time
	)
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT base_url,
		       model,
		       COALESCE(default_model, model) AS default_model,
		       COALESCE(agentic_model, COALESCE(default_model, model)) AS agentic_model,
		       COALESCE(translation_model, COALESCE(default_model, model)) AS translation_model,
		       COALESCE(batch_enabled, FALSE) AS batch_enabled,
		       COALESCE(batch_mode, 'realtime') AS batch_mode,
		       api_key_encrypted, timeout_seconds, auto_analysis_min_severity, updated_at
		FROM tenant_llm_configs
		WHERE tenant_id = $1`, claims.TenantID,
	).Scan(&baseURL, &model, &defaultModel, &agenticModel, &translationModel, &batchEnabled,
		&batchMode, &apiKey, &timeoutSeconds, &autoAnalysisMinSeverity, &updatedAt)

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
		Model:                   firstNonEmpty(model, defaultModel),
		DefaultModel:            defaultModel,
		AgenticModel:            agenticModel,
		TranslationModel:        translationModel,
		BatchEnabled:            batchEnabled,
		BatchMode:               batchMode,
		HasAPIKey:               len(apiKey) > 0,
		TimeoutSeconds:          timeoutSeconds,
		AutoAnalysisMinSeverity: autoAnalysisMinSeverity,
		UpdatedAt:               &updatedAt,
	})
}

type putLLMRequest struct {
	BaseURL                 string  `json:"base_url" binding:"required"`
	Model                   *string `json:"model"`
	DefaultModel            *string `json:"default_model"`
	AgenticModel            *string `json:"agentic_model"`
	TranslationModel        *string `json:"translation_model"`
	BatchEnabled            *bool   `json:"batch_enabled"`
	BatchMode               *string `json:"batch_mode"`
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
	legacyModel := trimOptionalString(req.Model)
	defaultModel := trimOptionalString(req.DefaultModel)
	if legacyModel != "" && defaultModel != "" && legacyModel != defaultModel {
		c.JSON(http.StatusBadRequest, gin.H{"error": "model and default_model must match when both are provided"})
		return
	}
	resolvedDefaultModel := firstNonEmpty(defaultModel, legacyModel)
	agenticModel := trimOptionalString(req.AgenticModel)
	translationModel := trimOptionalString(req.TranslationModel)
	batchEnabled := false
	if req.BatchEnabled != nil {
		batchEnabled = *req.BatchEnabled
	} else if existingBatch, err := h.loadBatchEnabled(c.Request.Context(), claims.TenantID); err == nil {
		batchEnabled = existingBatch
	}
	batchMode := "realtime"
	if req.BatchMode != nil {
		batchMode = strings.TrimSpace(*req.BatchMode)
	} else if existingBatchMode, err := h.loadBatchMode(c.Request.Context(), claims.TenantID); err == nil {
		batchMode = existingBatchMode
	}
	if batchMode != "realtime" && batchMode != "prefer_batch" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "batch_mode must be one of: realtime, prefer_batch"})
		return
	}
	if !batchEnabled {
		batchMode = "realtime"
	}
	if !isHTTPURL(baseURL) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "base_url must be a valid http(s) URL"})
		return
	}
	if resolvedDefaultModel == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "default_model (or legacy model) must not be empty"})
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
				(tenant_id, base_url, model, default_model, agentic_model, translation_model, batch_enabled, batch_mode,
				 api_key_encrypted, timeout_seconds, auto_analysis_min_severity,
				 updated_by_user_id, updated_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $10, $11, NOW(), NOW())
			ON CONFLICT (tenant_id) DO UPDATE SET
				base_url                    = EXCLUDED.base_url,
				model                       = EXCLUDED.model,
				default_model               = EXCLUDED.default_model,
				agentic_model               = EXCLUDED.agentic_model,
				translation_model           = EXCLUDED.translation_model,
				batch_enabled               = EXCLUDED.batch_enabled,
				batch_mode                  = EXCLUDED.batch_mode,
				timeout_seconds             = EXCLUDED.timeout_seconds,
				auto_analysis_min_severity  = EXCLUDED.auto_analysis_min_severity,
				updated_by_user_id          = EXCLUDED.updated_by_user_id,
				updated_at                  = NOW()`
		args = []any{
			claims.TenantID, baseURL, resolvedDefaultModel, resolvedDefaultModel,
			nullableString(agenticModel), nullableString(translationModel), batchEnabled, batchMode,
			timeoutSeconds, autoAnalysisMinSeverity, claims.UserID,
		}
	} else {
		query = `
			INSERT INTO tenant_llm_configs
				(tenant_id, base_url, model, default_model, agentic_model, translation_model, batch_enabled, batch_mode,
				 api_key_encrypted, timeout_seconds, auto_analysis_min_severity,
				 updated_by_user_id, updated_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
			ON CONFLICT (tenant_id) DO UPDATE SET
				base_url                    = EXCLUDED.base_url,
				model                       = EXCLUDED.model,
				default_model               = EXCLUDED.default_model,
				agentic_model               = EXCLUDED.agentic_model,
				translation_model           = EXCLUDED.translation_model,
				batch_enabled               = EXCLUDED.batch_enabled,
				batch_mode                  = EXCLUDED.batch_mode,
				api_key_encrypted           = EXCLUDED.api_key_encrypted,
				timeout_seconds             = EXCLUDED.timeout_seconds,
				auto_analysis_min_severity  = EXCLUDED.auto_analysis_min_severity,
				updated_by_user_id          = EXCLUDED.updated_by_user_id,
				updated_at                  = NOW()`
		args = []any{
			claims.TenantID, baseURL, resolvedDefaultModel, resolvedDefaultModel,
			nullableString(agenticModel), nullableString(translationModel), batchEnabled, batchMode,
			apiKeyEncrypted, timeoutSeconds, autoAnalysisMinSeverity, claims.UserID,
		}
	}

	if _, err := h.db.Exec(c.Request.Context(), query, args...); err != nil {
		h.log.Error("upsert llm config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	h.log.Info("llm config updated",
		zap.String("tenant_id", claims.TenantID.String()),
		zap.String("user_id", claims.UserID.String()),
		zap.String("default_model", resolvedDefaultModel),
		zap.String("batch_mode", batchMode),
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

func (h *SettingsHandler) loadBatchEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	var enabled bool
	err := h.db.QueryRow(ctx, `
		SELECT batch_enabled
		FROM tenant_llm_configs
		WHERE tenant_id = $1`, tenantID,
	).Scan(&enabled)
	return enabled, err
}

func (h *SettingsHandler) loadBatchMode(ctx context.Context, tenantID uuid.UUID) (string, error) {
	var batchMode string
	err := h.db.QueryRow(ctx, `
		SELECT COALESCE(batch_mode, 'realtime')
		FROM tenant_llm_configs
		WHERE tenant_id = $1`, tenantID,
	).Scan(&batchMode)
	return batchMode, err
}

func trimOptionalString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
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
