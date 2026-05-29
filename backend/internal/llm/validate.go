package llm

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// RequiredModelAliases documents the LiteLLM model aliases expected by Baldr.
// When model_list is versioned in litellm_config.yaml, these names must exist.
var RequiredModelAliases = []string{
	"gpt-4o-mini",
}

type ModelValidator struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	log        *zap.Logger
}

func NewModelValidator(baseURL, apiKey string, log *zap.Logger) *ModelValidator {
	return &ModelValidator{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		log:        log,
	}
}

// ValidateRequiredAliases checks that configured aliases resolve via LiteLLM.
// Failures are logged as warnings so startup is not blocked in partial setups.
func (v *ModelValidator) ValidateRequiredAliases(ctx context.Context, aliases ...string) {
	if v.baseURL == "" {
		return
	}
	required := aliases
	if len(required) == 0 {
		required = RequiredModelAliases
	}
	for _, alias := range required {
		if strings.TrimSpace(alias) == "" {
			continue
		}
		if err := v.probeModel(ctx, alias); err != nil {
			v.log.Warn("litellm model alias validation failed",
				zap.String("model", alias),
				zap.String("base_url", v.baseURL),
				zap.Error(err),
			)
			continue
		}
		v.log.Info("litellm model alias validated", zap.String("model", alias))
	}
}

func (v *ModelValidator) probeModel(ctx context.Context, model string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.baseURL+"/v1/models/"+model, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if v.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+v.apiKey)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call litellm: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("model alias not found")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("litellm returned %d", resp.StatusCode)
	}
	return nil
}
