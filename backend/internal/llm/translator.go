package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const TranslationPromptVersion = "v1-pt-br"

type AnalysisTranslationInput struct {
	Reasoning        string
	ExploitationPath string
	RemediationPath  string
}

type AnalysisTranslationResult struct {
	Reasoning        string `json:"reasoning"`
	ExploitationPath string `json:"exploitation_path"`
	RemediationPath  string `json:"remediation_path"`
}

func (c *Client) TranslateAnalysisToPtBR(ctx context.Context, input AnalysisTranslationInput) (*AnalysisTranslationResult, error) {
	if strings.TrimSpace(input.Reasoning) == "" &&
		strings.TrimSpace(input.ExploitationPath) == "" &&
		strings.TrimSpace(input.RemediationPath) == "" {
		return &AnalysisTranslationResult{}, nil
	}

	systemPrompt := `You translate security analysis text from English to Brazilian Portuguese (pt-BR).
Respond ONLY with valid JSON matching this schema:
{
  "reasoning": "translated reasoning or empty string",
  "exploitation_path": "translated exploitation path or empty string",
  "remediation_path": "translated remediation path or empty string"
}
Rules:
- Preserve technical identifiers exactly (CVE IDs, OSV IDs, package names, versions, file paths, function names, HTTP routes, env vars).
- Keep code snippets, paths, and line references unchanged.
- Use clear Brazilian Portuguese for explanatory prose.
- If a field is empty in the input, return an empty string for that field.`

	userPayload, err := json.Marshal(map[string]string{
		"reasoning":         input.Reasoning,
		"exploitation_path": input.ExploitationPath,
		"remediation_path":  input.RemediationPath,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal translation input: %w", err)
	}

	content, err := c.chatCompletionJSON(ctx, systemPrompt, string(userPayload))
	if err != nil {
		return nil, err
	}

	return parseAnalysisTranslationResult(content)
}

func parseAnalysisTranslationResult(content string) (*AnalysisTranslationResult, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result AnalysisTranslationResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse translation json: %w", err)
	}
	return &result, nil
}

func (c *Client) chatCompletionJSON(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature":     0.1,
		"response_format": map[string]string{"type": "json_object"},
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := newChatCompletionRequest(ctx, c.baseURL, c.apiKey, body)
	if err != nil {
		return "", err
	}

	respBody, statusCode, err := doChatCompletion(c.httpClient, req)
	if err != nil {
		return "", err
	}
	if statusCode >= 400 {
		return "", fmt.Errorf("litellm returned %d: %s", statusCode, truncate(string(respBody), 500))
	}

	return extractMessageContent(respBody)
}
