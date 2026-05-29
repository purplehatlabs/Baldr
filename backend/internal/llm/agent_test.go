package llm

import "testing"

func TestParseAgentAnalysisResult(t *testing.T) {
	raw := `{
		"is_critical": true,
		"is_exploitable": true,
		"criticality_verdict": "true_critical",
		"exploitability": "high",
		"confidence": 0.85,
		"reasoning": "user input reaches vulnerable API",
		"exploitation_path": "HTTP handler calls vulnerable function",
		"remediation_path": "upgrade package",
		"vulnerable_code_paths": ["src/handler.go:42"],
		"attack_surface_factors": ["internet_exposed"],
		"evidence_gaps": []
	}`

	result, err := ParseAgentAnalysisResult(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.VulnerableCodePaths) != 1 {
		t.Fatalf("expected vulnerable paths, got %v", result.VulnerableCodePaths)
	}
	if result.Exploitability != "high" {
		t.Fatalf("expected high exploitability, got %s", result.Exploitability)
	}
}
