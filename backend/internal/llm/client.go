package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/purplehatlabs/Baldr/internal/models"
)

const PromptVersion = "v1"

type FindingContext struct {
	OSVID          string
	PackageName    string
	PackageVersion string
	FixedVersion   string
	Severity       string
	CVSSScore      string
	Summary        string
	Details        string
	RepoFullName   string
	ManifestPath   string
	Ecosystem      string
	Status         string
}

type AnalysisResult struct {
	IsCritical         bool    `json:"is_critical"`
	IsExploitable      bool    `json:"is_exploitable"`
	CriticalityVerdict string  `json:"criticality_verdict"`
	Exploitability     string  `json:"exploitability"`
	Confidence         float64 `json:"confidence"`
	Reasoning          string  `json:"reasoning"`
	ExploitationPath   string  `json:"exploitation_path"`
	RemediationPath    string  `json:"remediation_path"`
}

// Settings is the minimal configuration needed to call the LLM endpoint.
// It is intentionally decoupled from any config source so it can come from
// env, DB, tests, etc.
type Settings struct {
	BaseURL                 string
	APIKey                  string
	Model                   string
	TimeoutSeconds          int
	AutoAnalysisMinSeverity models.Severity
}

type Client struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
}

// New constructs a Client from explicit Settings.
func New(s Settings) *Client {
	timeout := time.Duration(s.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Client{
		baseURL:    strings.TrimRight(s.BaseURL, "/"),
		apiKey:     s.APIKey,
		model:      s.Model,
		httpClient: &http.Client{Timeout: timeout},
	}
}

func (c *Client) ModelName() string {
	return c.model
}

func (c *Client) AnalyzeFinding(ctx context.Context, fc FindingContext) (*AnalysisResult, error) {
	systemPrompt := `You are a security engineer validating dependency vulnerability findings.
Analyze whether the finding is truly critical in the project context and whether it is exploitable.
Respond ONLY with valid JSON matching this schema:
{
  "is_critical": boolean,
  "is_exploitable": boolean,
  "criticality_verdict": "true_critical" | "false_positive" | "informational" | "needs_human_review",
  "exploitability": "none" | "low" | "medium" | "high" | "critical",
  "confidence": number between 0 and 1,
  "reasoning": "brief explanation of your assessment",
  "exploitation_path": "how an attacker could exploit this, or empty string if not exploitable",
  "remediation_path": "best remediation steps including version upgrade or mitigations"
}
Be conservative: if uncertain, use needs_human_review and lower confidence.`

	userPrompt := fmt.Sprintf(`Validate this dependency vulnerability finding:

Repository: %s
Manifest: %s
Ecosystem: %s
Package: %s@%s
Fixed version: %s
OSV ID: %s
Scanner severity: %s
CVSS: %s
Finding status: %s

Summary: %s

Details: %s`,
		fc.RepoFullName, fc.ManifestPath, fc.Ecosystem,
		fc.PackageName, fc.PackageVersion, nullDefault(fc.FixedVersion, "unknown"),
		fc.OSVID, fc.Severity, fc.CVSSScore, fc.Status,
		fc.Summary, truncate(fc.Details, 2000),
	)

	body, err := json.Marshal(map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature":     0.2,
		"response_format": map[string]string{"type": "json_object"},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call litellm: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("litellm returned %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	content, err := extractMessageContent(respBody)
	if err != nil {
		return nil, err
	}

	return ParseAnalysisResult(content)
}

func ParseAnalysisResult(content string) (*AnalysisResult, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result AnalysisResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse llm json: %w", err)
	}
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}
	return &result, nil
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func extractMessageContent(body []byte) (string, error) {
	var resp chatCompletionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parse chat completion: %w", err)
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("empty llm response")
	}
	return resp.Choices[0].Message.Content, nil
}

func nullDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
