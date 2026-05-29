package llm

import (
	"testing"
)

func TestParseAnalysisTranslationResult(t *testing.T) {
	raw := `{
		"reasoning": "O pacote é alcançável no código da aplicação.",
		"exploitation_path": "Entrada HTTP em routes/api.go:42",
		"remediation_path": "Atualizar django para >= 4.2.10"
	}`

	result, err := parseAnalysisTranslationResult(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reasoning == "" {
		t.Fatal("expected reasoning translation")
	}
	if result.ExploitationPath == "" {
		t.Fatal("expected exploitation_path translation")
	}
	if result.RemediationPath == "" {
		t.Fatal("expected remediation_path translation")
	}
}

func TestParseAnalysisTranslationResult_CodeBlock(t *testing.T) {
	raw := "```json\n{\"reasoning\":\"teste\",\"exploitation_path\":\"\",\"remediation_path\":\"\"}\n```"
	result, err := parseAnalysisTranslationResult(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reasoning != "teste" {
		t.Fatalf("expected teste, got %q", result.Reasoning)
	}
}
