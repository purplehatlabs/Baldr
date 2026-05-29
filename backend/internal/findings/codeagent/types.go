package codeagent

import (
	"encoding/json"

	"github.com/purplehatlabs/Baldr/internal/llm"
	"github.com/purplehatlabs/Baldr/internal/models"
)

const (
	MaxAgentTurns    = 200
	MaxToolCalls     = 40
	MaxImportSites   = 25
	DefaultMaxOutput = 8000
)

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
	ReachabilityStatus     models.ReachabilityStatus
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

type AgentTrace struct {
	Turns     int              `json:"turns"`
	ToolCalls int              `json:"tool_calls"`
	Duration  int64            `json:"duration_ms"`
	Steps     []AgentTraceStep `json:"steps,omitempty"`
}

type AgentTraceStep struct {
	Turn       int             `json:"turn"`
	ToolName   string          `json:"tool_name,omitempty"`
	ToolArgs   json.RawMessage `json:"tool_args,omitempty"`
	ToolResult string          `json:"tool_result,omitempty"`
}

type AgentRunResult struct {
	Analysis       *llm.AgentAnalysisResult
	Trace          AgentTrace
	VulnPaths      []string
	AgentTraceJSON []byte
	VulnPathsJSON  []byte
}
