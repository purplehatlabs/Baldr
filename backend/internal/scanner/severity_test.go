package scanner

import (
	"testing"

	osvmodels "github.com/google/osv-scanner/v2/pkg/models"
	internalmodels "github.com/purplehatlabs/Baldr/internal/models"
)

func TestClassifySeverity(t *testing.T) {
	tests := []struct {
		name      string
		vuln      osvmodels.Vulnerability
		wantLevel internalmodels.Severity
		wantHas   bool // whether a numeric score is returned
	}{
		{
			name: "numeric CVSS v3 score 9.8 → critical",
			vuln: osvmodels.Vulnerability{
				Severity: []osvmodels.Severity{
					{Type: osvmodels.SeverityCVSSV3, Score: "9.8"},
				},
			},
			wantLevel: internalmodels.SeverityCritical,
			wantHas:   true,
		},
		{
			name: "CVSS v3.1 vector → score parsed",
			vuln: osvmodels.Vulnerability{
				Severity: []osvmodels.Severity{
					{Type: osvmodels.SeverityCVSSV3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			wantLevel: internalmodels.SeverityCritical,
			wantHas:   true,
		},
		{
			name: "CVSS v3.0 vector → score parsed",
			vuln: osvmodels.Vulnerability{
				Severity: []osvmodels.Severity{
					{Type: osvmodels.SeverityCVSSV3, Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
				},
			},
			wantLevel: internalmodels.SeverityMedium,
			wantHas:   true,
		},
		{
			name: "CVSS v2 vector → score parsed",
			vuln: osvmodels.Vulnerability{
				Severity: []osvmodels.Severity{
					{Type: osvmodels.SeverityCVSSV2, Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
				},
			},
			wantLevel: internalmodels.SeverityHigh,
			wantHas:   true,
		},
		{
			name: "no CVSS, GHSA textual HIGH",
			vuln: osvmodels.Vulnerability{
				DatabaseSpecific: map[string]interface{}{"severity": "HIGH"},
			},
			wantLevel: internalmodels.SeverityHigh,
			wantHas:   false,
		},
		{
			name: "no CVSS, GHSA textual MODERATE → medium",
			vuln: osvmodels.Vulnerability{
				DatabaseSpecific: map[string]interface{}{"severity": "MODERATE"},
			},
			wantLevel: internalmodels.SeverityMedium,
			wantHas:   false,
		},
		{
			name: "CVSS overrides GHSA when both present",
			vuln: osvmodels.Vulnerability{
				Severity: []osvmodels.Severity{
					{Type: osvmodels.SeverityCVSSV3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
				},
				DatabaseSpecific: map[string]interface{}{"severity": "LOW"},
			},
			wantLevel: internalmodels.SeverityMedium,
			wantHas:   true,
		},
		{
			name:      "empty vuln → unknown",
			vuln:      osvmodels.Vulnerability{},
			wantLevel: internalmodels.SeverityUnknown,
			wantHas:   false,
		},
		{
			name: "invalid CVSS vector, no fallback → unknown",
			vuln: osvmodels.Vulnerability{
				Severity: []osvmodels.Severity{
					{Type: osvmodels.SeverityCVSSV3, Score: "not-a-vector"},
				},
			},
			wantLevel: internalmodels.SeverityUnknown,
			wantHas:   false,
		},
		{
			name: "highest score wins across multiple severity entries",
			vuln: osvmodels.Vulnerability{
				Severity: []osvmodels.Severity{
					{Type: osvmodels.SeverityCVSSV2, Score: "AV:L/AC:H/Au:S/C:N/I:N/A:P"},
					{Type: osvmodels.SeverityCVSSV3, Score: "9.8"},
				},
			},
			wantLevel: internalmodels.SeverityCritical,
			wantHas:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLevel, gotScore := classifySeverity(tc.vuln)
			if gotLevel != tc.wantLevel {
				t.Errorf("severity = %s, want %s", gotLevel, tc.wantLevel)
			}
			if tc.wantHas && gotScore == nil {
				t.Error("expected numeric score, got nil")
			}
			if !tc.wantHas && gotScore != nil {
				t.Errorf("expected nil score, got %v", *gotScore)
			}
		})
	}
}
