package codeagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/purplehatlabs/Baldr/internal/llm"
)

type AgentRunner struct {
	client *llm.AgentClient
}

func NewAgentRunner(client *llm.AgentClient) *AgentRunner {
	return &AgentRunner{client: client}
}

func (r *AgentRunner) Run(ctx context.Context, repoRoot string, bootstrap BootstrapContext) (*AgentRunResult, error) {
	start := time.Now()
	executor := NewToolExecutor(repoRoot, bootstrap.ImportSites, bootstrap.ImportSitesOmitted)
	tools := r.client.ToolDefinitions()

	llmBootstrap := llm.BootstrapContext{
		OSVID:                  bootstrap.OSVID,
		PackageName:            bootstrap.PackageName,
		PackageVersion:         bootstrap.PackageVersion,
		FixedVersion:           bootstrap.FixedVersion,
		Severity:               bootstrap.Severity,
		CVSSScore:              bootstrap.CVSSScore,
		Summary:                bootstrap.Summary,
		Details:                bootstrap.Details,
		RepoFullName:           bootstrap.RepoFullName,
		ManifestPath:           bootstrap.ManifestPath,
		Ecosystem:              bootstrap.Ecosystem,
		ReachabilityStatus:     string(bootstrap.ReachabilityStatus),
		ReachabilityConfidence: bootstrap.ReachabilityConfidence,
		ImportSites:            bootstrap.ImportSites,
		ImportSitesTotal:       bootstrap.ImportSitesTotal,
		ImportSitesOmitted:     bootstrap.ImportSitesOmitted,
		SearchHints:            bootstrap.SearchHints,
		IsInternetExposed:      bootstrap.IsInternetExposed,
		AssetCriticality:       bootstrap.AssetCriticality,
		DataSensitivity:        bootstrap.DataSensitivity,
		Environment:            bootstrap.Environment,
	}

	messages := []llm.ChatMessage{
		{Role: "system", Content: llm.BuildAgentSystemPrompt()},
		{Role: "user", Content: llm.BuildAgentBootstrapPrompt(llmBootstrap)},
	}

	trace := AgentTrace{Steps: []AgentTraceStep{}}
	toolCalls := 0

	for turn := 0; turn < MaxAgentTurns; turn++ {
		trace.Turns = turn + 1
		assistant, err := r.client.Chat(ctx, messages, tools)
		if err != nil {
			return nil, fmt.Errorf("agent chat turn %d: %w", turn+1, err)
		}

		if len(assistant.ToolCalls) == 0 {
			content := strings.TrimSpace(assistant.Content)
			if content == "" {
				return nil, fmt.Errorf("agent returned empty final response")
			}
			analysis, err := llm.ParseAgentAnalysisResult(content)
			if err != nil {
				return nil, err
			}
			trace.ToolCalls = toolCalls
			trace.Duration = time.Since(start).Milliseconds()
			return r.buildResult(analysis, trace)
		}

		messages = append(messages, assistant)
		for _, tc := range assistant.ToolCalls {
			if toolCalls >= MaxToolCalls {
				return nil, fmt.Errorf("agent exceeded max tool calls (%d)", MaxToolCalls)
			}
			toolCalls++
			result, err := executor.Execute(tc.Name, tc.Arguments)
			if err != nil {
				result = "error: " + err.Error()
			}
			trace.Steps = append(trace.Steps, AgentTraceStep{
				Turn:       turn + 1,
				ToolName:   tc.Name,
				ToolArgs:   tc.Arguments,
				ToolResult: truncateOutput(result, 500),
			})
			messages = append(messages, llm.ChatMessage{
				Role:       "tool",
				ToolCallID: tc.ID,
				Content:    result,
			})
		}
	}

	return nil, fmt.Errorf("agent exceeded max turns (%d)", MaxAgentTurns)
}

func (r *AgentRunner) buildResult(analysis *llm.AgentAnalysisResult, trace AgentTrace) (*AgentRunResult, error) {
	traceJSON, err := json.Marshal(trace)
	if err != nil {
		return nil, err
	}
	pathsJSON, err := json.Marshal(analysis.VulnerableCodePaths)
	if err != nil {
		return nil, err
	}
	return &AgentRunResult{
		Analysis:       analysis,
		Trace:          trace,
		VulnPaths:      analysis.VulnerableCodePaths,
		AgentTraceJSON: traceJSON,
		VulnPathsJSON:  pathsJSON,
	}, nil
}
