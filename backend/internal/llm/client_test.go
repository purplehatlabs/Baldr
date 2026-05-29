package llm

import "testing"

func TestParseAnalysisResult_ValidJSON(t *testing.T) {
	content := `{
		"is_critical": true,
		"is_exploitable": false,
		"criticality_verdict": "true_critical",
		"exploitability": "none",
		"confidence": 0.85,
		"reasoning": "Confirmed RCE in dependency used at runtime.",
		"exploitation_path": "",
		"remediation_path": "Upgrade to patched version 1.2.3"
	}`

	result, err := ParseAnalysisResult(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsCritical {
		t.Fatal("expected is_critical true")
	}
	if result.Exploitability != "none" {
		t.Fatalf("expected exploitability none, got %s", result.Exploitability)
	}
	if result.Confidence != 0.85 {
		t.Fatalf("expected confidence 0.85, got %f", result.Confidence)
	}
}

func TestParseAnalysisResult_ClampsConfidence(t *testing.T) {
	content := `{
		"is_critical": false,
		"is_exploitable": false,
		"criticality_verdict": "informational",
		"exploitability": "none",
		"confidence": 1.5,
		"reasoning": "test",
		"exploitation_path": "",
		"remediation_path": "none"
	}`

	result, err := ParseAnalysisResult(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Confidence != 1 {
		t.Fatalf("expected confidence clamped to 1, got %f", result.Confidence)
	}
}

func TestParseAnalysisResult_CodeBlock(t *testing.T) {
	content := "```json\n{\"is_critical\":false,\"is_exploitable\":false,\"criticality_verdict\":\"informational\",\"exploitability\":\"none\",\"confidence\":0.5,\"reasoning\":\"ok\",\"exploitation_path\":\"\",\"remediation_path\":\"upgrade\"}\n```"

	result, err := ParseAnalysisResult(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RemediationPath != "upgrade" {
		t.Fatalf("expected remediation upgrade, got %s", result.RemediationPath)
	}
}
