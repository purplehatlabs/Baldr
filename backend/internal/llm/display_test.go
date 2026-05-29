package llm

import "testing"

func TestDisplayText(t *testing.T) {
	if got := DisplayText("pt", "en"); got != "pt" {
		t.Fatalf("expected pt, got %q", got)
	}
	if got := DisplayText("", "en"); got != "en" {
		t.Fatalf("expected en fallback, got %q", got)
	}
	if got := DisplayText("", ""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}
