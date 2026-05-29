package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const AgentPromptVersion = "v2-agent"

type AgentAnalysisResult struct {
	AnalysisResult
	VulnerableCodePaths  []string `json:"vulnerable_code_paths"`
	AttackSurfaceFactors []string `json:"attack_surface_factors"`
	EvidenceGaps         []string `json:"evidence_gaps"`
}

type ToolCall struct {
	ID        string
	Name      string
	Arguments json.RawMessage
}

type ChatMessage struct {
	Role       string
	Content    string
	ToolCalls  []ToolCall
	ToolCallID string
	Cacheable  bool
}

type CompletionUsage struct {
	PromptTokens             int `json:"prompt_tokens"`
	CompletionTokens         int `json:"completion_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

type AgentClient struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
	log        *zap.Logger
}

func NewAgentClient(s Settings, log *zap.Logger) *AgentClient {
	timeout := time.Duration(s.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &AgentClient{
		baseURL:    strings.TrimRight(s.BaseURL, "/"),
		apiKey:     s.APIKey,
		model:      s.ResolveAgenticModel(),
		httpClient: &http.Client{Timeout: timeout},
		log:        log,
	}
}

func (c *AgentClient) ModelName() string {
	return c.model
}

func (c *AgentClient) ToolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"type": "function",
			"function": map[string]any{
				"name":        "search_code",
				"description": "Search for a text query in repository source files. Returns matching file:line:content entries.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "Text to search for in source files",
						},
						"path_glob": map[string]any{
							"type":        "string",
							"description": "Optional filename glob such as *.go or *.py",
						},
					},
					"required": []string{"query"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "read_file",
				"description": "Read lines from a repository file relative to repo root.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{
							"type":        "string",
							"description": "Relative file path",
						},
						"start_line": map[string]any{
							"type":        "integer",
							"description": "Optional 1-based start line",
						},
						"end_line": map[string]any{
							"type":        "integer",
							"description": "Optional 1-based end line",
						},
					},
					"required": []string{"path"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "list_import_sites",
				"description": "List files where the vulnerable package is referenced according to reachability heuristics.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"package_name": map[string]any{
							"type":        "string",
							"description": "Package name to list import sites for",
						},
					},
					"required": []string{"package_name"},
				},
			},
		},
	}
}

func (c *AgentClient) Chat(ctx context.Context, messages []ChatMessage, tools []map[string]any) (ChatMessage, CompletionUsage, error) {
	payloadMessages := make([]map[string]any, 0, len(messages))
	for _, m := range messages {
		payloadMessages = append(payloadMessages, encodeChatMessage(m))
	}

	bodyMap := map[string]any{
		"model":       c.model,
		"messages":    payloadMessages,
		"tools":       tools,
		"tool_choice": "auto",
		"temperature": 0.2,
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return ChatMessage{}, CompletionUsage{}, fmt.Errorf("marshal request: %w", err)
	}

	msg, usage, err := c.doChat(ctx, body)
	if err != nil {
		return ChatMessage{}, usage, err
	}
	c.logCacheUsage(usage)
	return msg, usage, nil
}

func (c *AgentClient) FinalizeStructuredResult(ctx context.Context, messages []ChatMessage) (*AgentAnalysisResult, CompletionUsage, error) {
	payloadMessages := make([]map[string]any, 0, len(messages)+1)
	for _, m := range messages {
		payloadMessages = append(payloadMessages, encodeChatMessage(m))
	}
	payloadMessages = append(payloadMessages, map[string]any{
		"role":    "user",
		"content": "Return your final assessment now as JSON only, matching the required schema.",
	})

	body, err := json.Marshal(map[string]any{
		"model":    c.model,
		"messages": payloadMessages,
		"response_format": map[string]string{
			"type": "json_object",
		},
		"temperature": 0.1,
	})
	if err != nil {
		return nil, CompletionUsage{}, fmt.Errorf("marshal finalize request: %w", err)
	}

	msg, usage, err := c.doChat(ctx, body)
	if err != nil {
		return nil, usage, err
	}
	c.logCacheUsage(usage)

	result, err := ParseAgentAnalysisResult(msg.Content)
	if err != nil {
		return nil, usage, err
	}
	return result, usage, nil
}

func (c *AgentClient) doChat(ctx context.Context, body []byte) (ChatMessage, CompletionUsage, error) {
	req, err := newChatCompletionRequest(ctx, c.baseURL, c.apiKey, body)
	if err != nil {
		return ChatMessage{}, CompletionUsage{}, err
	}

	respBody, statusCode, err := doChatCompletionWithRetry(ctx, c.httpClient, req)
	if err != nil {
		return ChatMessage{}, CompletionUsage{}, err
	}
	if statusCode >= 400 {
		return ChatMessage{}, CompletionUsage{}, fmt.Errorf("litellm returned %d: %s", statusCode, truncate(string(respBody), 500))
	}

	msg, usage, err := parseAssistantMessageWithUsage(respBody)
	if err != nil {
		return ChatMessage{}, usage, err
	}
	return msg, usage, nil
}

func encodeChatMessage(m ChatMessage) map[string]any {
	if m.ToolCallID != "" {
		return map[string]any{
			"role":         m.Role,
			"content":      m.Content,
			"tool_call_id": m.ToolCallID,
		}
	}
	if len(m.ToolCalls) > 0 {
		toolCalls := make([]map[string]any, 0, len(m.ToolCalls))
		for _, tc := range m.ToolCalls {
			toolCalls = append(toolCalls, map[string]any{
				"id":   tc.ID,
				"type": "function",
				"function": map[string]any{
					"name":      tc.Name,
					"arguments": string(tc.Arguments),
				},
			})
		}
		msg := map[string]any{"role": m.Role, "tool_calls": toolCalls}
		if m.Content != "" {
			msg["content"] = m.Content
		}
		return msg
	}
	if m.Cacheable && m.Content != "" {
		return map[string]any{
			"role": m.Role,
			"content": []map[string]any{
				{
					"type": "text",
					"text": m.Content,
					"cache_control": map[string]string{
						"type": "ephemeral",
					},
				},
			},
		}
	}
	msg := map[string]any{"role": m.Role}
	if m.Content != "" {
		msg["content"] = m.Content
	}
	return msg
}

func (c *AgentClient) logCacheUsage(usage CompletionUsage) {
	if c.log == nil {
		return
	}
	if usage.CacheReadInputTokens == 0 && usage.CacheCreationInputTokens == 0 {
		return
	}
	c.log.Info("agent prompt cache usage",
		zap.Int("prompt_tokens", usage.PromptTokens),
		zap.Int("cache_creation_input_tokens", usage.CacheCreationInputTokens),
		zap.Int("cache_read_input_tokens", usage.CacheReadInputTokens),
	)
}

func parseAssistantMessageWithUsage(body []byte) (ChatMessage, CompletionUsage, error) {
	var resp struct {
		Usage struct {
			PromptTokens             int `json:"prompt_tokens"`
			CompletionTokens         int `json:"completion_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		} `json:"usage"`
		Choices []struct {
			Message struct {
				Role      string `json:"role"`
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ChatMessage{}, CompletionUsage{}, fmt.Errorf("parse chat completion: %w", err)
	}
	if len(resp.Choices) == 0 {
		return ChatMessage{}, CompletionUsage{}, fmt.Errorf("empty llm response")
	}
	msg := resp.Choices[0].Message
	out := ChatMessage{Role: msg.Role, Content: msg.Content}
	for _, tc := range msg.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: json.RawMessage(tc.Function.Arguments),
		})
	}
	usage := CompletionUsage{
		PromptTokens:             resp.Usage.PromptTokens,
		CompletionTokens:         resp.Usage.CompletionTokens,
		CacheCreationInputTokens: resp.Usage.CacheCreationInputTokens,
		CacheReadInputTokens:     resp.Usage.CacheReadInputTokens,
	}
	return out, usage, nil
}

func ParseAgentAnalysisResult(content string) (*AgentAnalysisResult, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result AgentAnalysisResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse agent json: %w", err)
	}
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}
	return &result, nil
}

func BuildAgentSystemPrompt() string {
	return `You are a security engineer analyzing dependency vulnerabilities in a real codebase.
Use the provided tools to inspect source code before concluding exploitability.
Your job is to determine whether the vulnerability is truly exploitable in THIS project.

Budget: you may use tools across many rounds (up to 40 tool rounds). Investigate efficiently — avoid repeating broad searches.

Workflow:
1. Review bootstrap context (CVE, package, exposure, reachability, advisory search hints).
2. Call list_import_sites, then read_file on 1-2 likely application entrypoints before broad search_code.
3. For framework/library CVEs (django, flask, rails, express, spring, etc.): search advisory-specific API patterns from the hints — NOT the package name alone (e.g. search "_connector" with path_glob "*.py", not "django").
4. Use search_code with path_glob (*.py, *.go, *.js) to narrow results in large repos.
5. Use read_file to inspect call sites and data flow when needed.
6. When done investigating, respond with ONLY valid JSON (no markdown) matching:
{
  "is_critical": boolean,
  "is_exploitable": boolean,
  "criticality_verdict": "true_critical" | "false_positive" | "informational" | "needs_human_review",
  "exploitability": "none" | "low" | "medium" | "high" | "critical",
  "confidence": number between 0 and 1,
  "reasoning": "brief explanation grounded in code evidence",
  "exploitation_path": "concrete attack path or empty string",
  "remediation_path": "upgrade or mitigation steps",
  "vulnerable_code_paths": ["relative/path.go:42"],
  "attack_surface_factors": ["internet_exposed", "user_input_reaches_package"],
  "evidence_gaps": ["what you could not verify"]
}
Be conservative: if code evidence is insufficient, use needs_human_review and lower confidence.
Weight internet exposure and reachable vulnerable paths heavily.`
}

func BuildAgentBootstrapPrompt(ctx BootstrapContext) string {
	conf := "unknown"
	if ctx.ReachabilityConfidence != nil {
		conf = fmt.Sprintf("%.2f", *ctx.ReachabilityConfidence)
	}
	exposure := "unknown"
	if ctx.IsInternetExposed != nil {
		if *ctx.IsInternetExposed {
			exposure = "internet_exposed"
		} else {
			exposure = "internal_only"
		}
	}
	sites := "none"
	if len(ctx.ImportSites) > 0 {
		sites = strings.Join(ctx.ImportSites, ", ")
		if ctx.ImportSitesOmitted > 0 {
			sites += fmt.Sprintf(" (+%d more omitted)", ctx.ImportSitesOmitted)
		}
	} else if ctx.ImportSitesTotal > 0 {
		sites = fmt.Sprintf("none after filtering (%d raw reachability matches were manifest/lockfile-only)", ctx.ImportSitesTotal)
	}
	hints := "none"
	if len(ctx.SearchHints) > 0 {
		hints = strings.Join(ctx.SearchHints, ", ")
	}
	return fmt.Sprintf(`Analyze this finding in repository context:

Repository: %s
Manifest: %s
Ecosystem: %s
Package: %s@%s
Fixed version: %s
OSV ID: %s
Scanner severity: %s
CVSS: %s

Exposure: %s
Environment: %s
Asset criticality: %s
Data sensitivity: %s
Reachability: %s (confidence %s)
Application import sites (%d raw, filtered): %s
Advisory search hints (prefer these in search_code): %s

Summary: %s

Advisory details: %s

Investigate the codebase with tools, then return the final JSON assessment.`,
		ctx.RepoFullName, ctx.ManifestPath, ctx.Ecosystem,
		ctx.PackageName, ctx.PackageVersion, nullDefault(ctx.FixedVersion, "unknown"),
		ctx.OSVID, ctx.Severity, ctx.CVSSScore,
		exposure, ctx.Environment, ctx.AssetCriticality, ctx.DataSensitivity,
		ctx.ReachabilityStatus, conf, ctx.ImportSitesTotal, sites, hints,
		ctx.Summary, truncate(ctx.Details, 3000),
	)
}

// BootstrapContext mirrors codeagent.BootstrapContext for prompt building without import cycle.
type BootstrapContext struct {
	OSVID                  string
	PackageName            string
	PackageVersion         string
	FixedVersion           string
	Severity               string
	CVSSScore              string
	Summary                string
	Details                string
	RepoFullName           string
	ManifestPath           string
	Ecosystem              string
	ReachabilityStatus     string
	ReachabilityConfidence *float64
	ImportSites            []string
	ImportSitesTotal       int
	ImportSitesOmitted     int
	SearchHints            []string
	IsInternetExposed      *bool
	AssetCriticality       string
	DataSensitivity        string
	Environment            string
}
