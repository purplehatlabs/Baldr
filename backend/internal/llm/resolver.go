package llm

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/crypto"
	"github.com/purplehatlabs/Baldr/internal/models"
)

// Resolver returns LLM Settings for a given tenant. When the tenant has no
// configuration in tenant_llm_configs, it falls back to the process-level
// defaults (Fallback) so existing dev setups keep working.
type Resolver struct {
	db       *pgxpool.Pool
	encKey   []byte
	fallback Settings
}

func NewResolver(db *pgxpool.Pool, encKey []byte, fallback Settings) *Resolver {
	if fallback.AutoAnalysisMinSeverity == "" {
		fallback.AutoAnalysisMinSeverity = DefaultAutoAnalysisMinSeverity
	}
	return &Resolver{db: db, encKey: encKey, fallback: fallback}
}

// ResolveAutoAnalysisMinSeverity returns the tenant threshold for automatic
// LLM analysis. Tenants without a row use DefaultAutoAnalysisMinSeverity.
func (r *Resolver) ResolveAutoAnalysisMinSeverity(ctx context.Context, tenantID uuid.UUID) (models.Severity, error) {
	var minSeverity string
	err := r.db.QueryRow(ctx, `
		SELECT auto_analysis_min_severity
		FROM tenant_llm_configs
		WHERE tenant_id = $1`, tenantID,
	).Scan(&minSeverity)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultAutoAnalysisMinSeverity, nil
	}
	if err != nil {
		return "", fmt.Errorf("load tenant auto-analysis min severity: %w", err)
	}
	parsed, err := ParseAutoAnalysisMinSeverity(minSeverity)
	if err != nil {
		return DefaultAutoAnalysisMinSeverity, nil
	}
	return parsed, nil
}

// Resolve returns the effective Settings for the tenant. The tenant config
// always wins; missing fields are filled from the fallback so a tenant can
// override only a subset (e.g. just the model).
func (r *Resolver) Resolve(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	var (
		baseURL                 string
		model                   string
		defaultModel            string
		agenticModel            *string
		translationModel        *string
		batchEnabled            bool
		batchMode               string
		apiKeyEncBytes          []byte
		timeoutSeconds          int
		autoAnalysisMinSeverity string
	)
	err := r.db.QueryRow(ctx, `
		SELECT base_url, model, COALESCE(default_model, model) AS default_model,
		       agentic_model, translation_model, batch_enabled,
		       COALESCE(batch_mode, 'realtime') AS batch_mode,
		       api_key_encrypted, timeout_seconds, auto_analysis_min_severity
		FROM tenant_llm_configs
		WHERE tenant_id = $1`, tenantID,
	).Scan(&baseURL, &model, &defaultModel, &agenticModel, &translationModel, &batchEnabled,
		&batchMode, &apiKeyEncBytes, &timeoutSeconds, &autoAnalysisMinSeverity)

	if errors.Is(err, pgx.ErrNoRows) {
		if r.fallback.BaseURL == "" || r.fallback.ResolveDefaultModel() == "" {
			return Settings{}, fmt.Errorf("tenant %s has no LLM config and no fallback is set", tenantID)
		}
		return r.fallback, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("load tenant LLM config: %w", err)
	}

	apiKey := ""
	if len(apiKeyEncBytes) > 0 {
		plain, err := crypto.Decrypt(apiKeyEncBytes, r.encKey)
		if err != nil {
			return Settings{}, fmt.Errorf("decrypt LLM api key: %w", err)
		}
		apiKey = string(plain)
	}

	minSeverity, err := ParseAutoAnalysisMinSeverity(autoAnalysisMinSeverity)
	if err != nil {
		minSeverity = DefaultAutoAnalysisMinSeverity
	}

	resolvedDefaultModel := firstNonEmpty(defaultModel, model, r.fallback.ResolveDefaultModel())
	resolvedAgenticModel := firstNonEmpty(derefString(agenticModel), r.fallback.AgenticModel, resolvedDefaultModel)
	resolvedTranslationModel := firstNonEmpty(derefString(translationModel), r.fallback.TranslationModel, resolvedDefaultModel)

	return Settings{
		BaseURL:                 firstNonEmpty(baseURL, r.fallback.BaseURL),
		APIKey:                  firstNonEmpty(apiKey, r.fallback.APIKey),
		Model:                   firstNonEmpty(model, resolvedDefaultModel),
		DefaultModel:            resolvedDefaultModel,
		AgenticModel:            resolvedAgenticModel,
		TranslationModel:        resolvedTranslationModel,
		BatchEnabled:            batchEnabled || r.fallback.BatchEnabled,
		BatchMode:               firstNonEmpty(batchMode, r.fallback.BatchMode, "realtime"),
		TimeoutSeconds:          firstPositive(timeoutSeconds, r.fallback.TimeoutSeconds),
		AutoAnalysisMinSeverity: minSeverity,
	}, nil
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}
