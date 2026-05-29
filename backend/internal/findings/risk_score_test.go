package findings

import (
	"testing"
	"time"

	"github.com/purplehatlabs/Baldr/internal/models"
)

func TestCalculateRiskScore_ReachableCritical(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-48 * time.Hour)
	conf := 0.8
	exploit := models.ExploitHigh

	result := CalculateRiskScore(RiskScoreInput{
		Severity:               models.SeverityCritical,
		Status:                 models.FindingOpen,
		FirstSeenAt:            firstSeen,
		ReachabilityStatus:     models.ReachabilityReachable,
		ReachabilityConfidence: &conf,
		Exploitability:         &exploit,
		IsInternetExposed:      boolPtr(true),
		AssetCriticality:       "critical",
		DataSensitivity:        "restricted",
		Environment:            "prod",
	}, now)

	if result.Score < 50 {
		t.Fatalf("expected high score, got %f", result.Score)
	}
	if result.Tier != models.RiskTierCritical && result.Tier != models.RiskTierHigh {
		t.Fatalf("expected high tier, got %s", result.Tier)
	}
}

func TestCalculateRiskScore_KEVReachableForcesHighTier(t *testing.T) {
	result := CalculateRiskScore(RiskScoreInput{
		Severity:           models.SeverityLow,
		Status:             models.FindingOpen,
		FirstSeenAt:        time.Now().UTC(),
		ReachabilityStatus: models.ReachabilityReachable,
		KEVListed:          true,
	}, time.Now().UTC())

	if result.Tier != models.RiskTierHigh && result.Tier != models.RiskTierCritical {
		t.Fatalf("expected high-or-above tier due to KEV override, got %s", result.Tier)
	}
}

func TestCalculateRiskScore_UnreachableCriticalLowThreatDowngrades(t *testing.T) {
	result := CalculateRiskScore(RiskScoreInput{
		Severity:           models.SeverityCritical,
		Status:             models.FindingOpen,
		FirstSeenAt:        time.Now().UTC().Add(-2 * time.Hour),
		ReachabilityStatus: models.ReachabilityUnreachable,
		EPSSScore:          floatPtr(0.01),
		KEVListed:          false,
	}, time.Now().UTC())

	if result.Tier == models.RiskTierCritical {
		t.Fatalf("expected downgrade override to avoid critical tier for unreachable low-threat finding")
	}
}

func TestCalculateRiskScore_UnreachableReducesScore(t *testing.T) {
	now := time.Now().UTC()
	reachable := CalculateRiskScore(RiskScoreInput{
		Severity:           models.SeverityHigh,
		Status:             models.FindingOpen,
		FirstSeenAt:        now.Add(-24 * time.Hour),
		ReachabilityStatus: models.ReachabilityReachable,
	}, now)
	unreachable := CalculateRiskScore(RiskScoreInput{
		Severity:           models.SeverityHigh,
		Status:             models.FindingOpen,
		FirstSeenAt:        now.Add(-24 * time.Hour),
		ReachabilityStatus: models.ReachabilityUnreachable,
	}, now)

	if unreachable.Score >= reachable.Score {
		t.Fatalf("unreachable score %f should be lower than reachable %f", unreachable.Score, reachable.Score)
	}
}

func TestCalculateRiskScore_SuppressedIsZero(t *testing.T) {
	result := CalculateRiskScore(RiskScoreInput{
		Severity: models.SeverityCritical,
		Status:   models.FindingSuppressed,
	}, time.Now())

	if result.Score != 0 {
		t.Fatalf("expected score 0, got %f", result.Score)
	}
}

func TestEvaluateSLA_Breach(t *testing.T) {
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-10 * 24 * time.Hour)
	_, breached := evaluateSLA(RiskScoreInput{
		Severity:    models.SeverityCritical,
		Status:      models.FindingOpen,
		FirstSeenAt: firstSeen,
	}, now)
	if !breached {
		t.Fatal("expected SLA breach for 10-day-old critical finding")
	}
}

func TestCalculateRiskScore_FalsePositiveReducesSeverityWeight(t *testing.T) {
	verdict := models.VerdictFalsePositive
	exploit := models.ExploitNone
	result := CalculateRiskScore(RiskScoreInput{
		Severity:              models.SeverityCritical,
		Status:                models.FindingOpen,
		FirstSeenAt:           time.Now().UTC(),
		CriticalityVerdict:    &verdict,
		Exploitability:        &exploit,
		LLMConfidence:         floatPtr(0.9),
		HasContextualAnalysis: true,
	}, time.Now().UTC())

	base := CalculateRiskScore(RiskScoreInput{
		Severity:    models.SeverityCritical,
		Status:      models.FindingOpen,
		FirstSeenAt: time.Now().UTC(),
	}, time.Now().UTC())

	if result.Score >= base.Score {
		t.Fatalf("false positive score %f should be lower than base %f", result.Score, base.Score)
	}
}

func TestCalculateRiskScore_VulnerablePathBoost(t *testing.T) {
	exploit := models.ExploitHigh
	withPath := CalculateRiskScore(RiskScoreInput{
		Severity:                models.SeverityHigh,
		Status:                  models.FindingOpen,
		FirstSeenAt:             time.Now().UTC(),
		Exploitability:          &exploit,
		LLMConfidence:           floatPtr(0.9),
		VulnerablePathConfirmed: true,
		HasContextualAnalysis:   true,
	}, time.Now().UTC())
	withoutPath := CalculateRiskScore(RiskScoreInput{
		Severity:              models.SeverityHigh,
		Status:                models.FindingOpen,
		FirstSeenAt:           time.Now().UTC(),
		Exploitability:        &exploit,
		LLMConfidence:         floatPtr(0.9),
		HasContextualAnalysis: true,
	}, time.Now().UTC())

	if withPath.Score <= withoutPath.Score {
		t.Fatalf("vulnerable path score %f should exceed non-path score %f", withPath.Score, withoutPath.Score)
	}
}

func TestCalculateRiskScore_InternetExposedExploitableMinimumHigh(t *testing.T) {
	exploit := models.ExploitHigh
	result := CalculateRiskScore(RiskScoreInput{
		Severity:              models.SeverityMedium,
		Status:                models.FindingOpen,
		FirstSeenAt:           time.Now().UTC(),
		Exploitability:        &exploit,
		IsInternetExposed:     boolPtr(true),
		HasContextualAnalysis: true,
	}, time.Now().UTC())

	if result.Tier != models.RiskTierHigh && result.Tier != models.RiskTierCritical {
		t.Fatalf("expected high tier override, got %s", result.Tier)
	}
}

func TestCalculateRiskScore_CriticalReachableExposedExploitableForcesCritical(t *testing.T) {
	exploit := models.ExploitHigh
	result := CalculateRiskScore(RiskScoreInput{
		Severity:              models.SeverityCritical,
		Status:                models.FindingOpen,
		FirstSeenAt:           time.Now().UTC(),
		ReachabilityStatus:    models.ReachabilityReachable,
		Exploitability:        &exploit,
		IsInternetExposed:     boolPtr(true),
		HasContextualAnalysis: true,
	}, time.Now().UTC())

	if result.Tier != models.RiskTierCritical {
		t.Fatalf("expected forced critical tier override, got %s", result.Tier)
	}
}

func TestCalculateRiskScore_ProductionAliasMapsToProd(t *testing.T) {
	scoreProd, _ := calculateBusinessScore(RiskScoreInput{
		Environment: "prod",
	})
	scoreProduction, _ := calculateBusinessScore(RiskScoreInput{
		Environment: "production",
	})

	if scoreProduction != scoreProd {
		t.Fatalf("expected production alias to match prod score, got production=%f prod=%f", scoreProduction, scoreProd)
	}
}

func floatPtr(v float64) *float64 {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}
