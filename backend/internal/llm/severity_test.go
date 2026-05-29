package llm

import (
	"testing"

	"github.com/purplehatlabs/Baldr/internal/models"
)

func TestMeetsMinSeverity(t *testing.T) {
	tests := []struct {
		finding models.Severity
		min     models.Severity
		want    bool
	}{
		{models.SeverityCritical, models.SeverityHigh, true},
		{models.SeverityHigh, models.SeverityHigh, true},
		{models.SeverityMedium, models.SeverityHigh, false},
		{models.SeverityLow, models.SeverityHigh, false},
		{models.SeverityUnknown, models.SeverityHigh, false},
		{models.SeverityMedium, models.SeverityMedium, true},
		{models.SeverityCritical, models.SeverityCritical, true},
		{models.SeverityHigh, models.SeverityCritical, false},
	}

	for _, tt := range tests {
		got := MeetsMinSeverity(tt.finding, tt.min)
		if got != tt.want {
			t.Fatalf("MeetsMinSeverity(%q, %q) = %v, want %v", tt.finding, tt.min, got, tt.want)
		}
	}
}

func TestParseAutoAnalysisMinSeverity(t *testing.T) {
	got, err := ParseAutoAnalysisMinSeverity(" HIGH ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != models.SeverityHigh {
		t.Fatalf("expected high, got %q", got)
	}

	if _, err := ParseAutoAnalysisMinSeverity("low"); err == nil {
		t.Fatal("expected error for low severity threshold")
	}
}
