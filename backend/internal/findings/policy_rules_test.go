package findings

import (
	"testing"
	"time"

	"github.com/purplehatlabs/Baldr/internal/models"
)

func TestCalculateRiskScore_WithRiskScoreThresholdPolicyHours(t *testing.T) {
	slaHours := 48
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-72 * time.Hour)

	result := CalculateRiskScore(RiskScoreInput{
		Severity:    models.SeverityHigh,
		Status:      models.FindingOpen,
		FirstSeenAt: firstSeen,
		SLAHours:    &slaHours,
	}, now)

	if result.SLADueAt == nil {
		t.Fatal("expected sla due date")
	}
	if !result.IsSLABreach {
		t.Fatal("expected SLA breach with 72h age and 48h SLA")
	}
}
