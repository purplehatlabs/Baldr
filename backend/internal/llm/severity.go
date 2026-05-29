package llm

import (
	"fmt"
	"strings"

	"github.com/purplehatlabs/Baldr/internal/models"
)

const DefaultAutoAnalysisMinSeverity = models.SeverityHigh

func SeverityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 1
	default:
		return 0
	}
}

func MeetsMinSeverity(finding, min models.Severity) bool {
	return SeverityRank(finding) >= SeverityRank(min)
}

func ParseAutoAnalysisMinSeverity(raw string) (models.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(models.SeverityCritical):
		return models.SeverityCritical, nil
	case string(models.SeverityHigh):
		return models.SeverityHigh, nil
	case string(models.SeverityMedium):
		return models.SeverityMedium, nil
	default:
		return "", fmt.Errorf("invalid auto_analysis_min_severity: %q", raw)
	}
}

func ValidAutoAnalysisMinSeverity(s models.Severity) bool {
	switch s {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium:
		return true
	default:
		return false
	}
}
