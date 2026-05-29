package codeagent

import (
	"strings"
	"testing"
)

func TestExtractAdvisorySearchHints_djangoConnector(t *testing.T) {
	summary := "Django vulnerable to SQL injection via `_connector` keyword argument in QuerySet and Q objects."
	details := "An issue in QuerySet.filter when `_connector` is passed from untrusted input."

	hints := ExtractAdvisorySearchHints(summary, details)
	if len(hints) == 0 {
		t.Fatal("expected hints")
	}
	foundConnector := false
	for _, h := range hints {
		if h == "_connector" {
			foundConnector = true
		}
	}
	if !foundConnector {
		t.Fatalf("expected _connector in hints, got %v", hints)
	}
}

func TestExtractAdvisorySearchHints_skipsNoise(t *testing.T) {
	hints := ExtractAdvisorySearchHints("See https://example.com/cve", "none")
	for _, h := range hints {
		if strings.HasPrefix(strings.ToLower(h), "http") || h == "none" {
			t.Fatalf("unexpected noise hint: %q", h)
		}
	}
}
