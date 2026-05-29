package findings

import (
	"testing"

	"github.com/purplehatlabs/Baldr/internal/llm"
	"github.com/purplehatlabs/Baldr/internal/models"
)

func TestApplyPreRules_SkipSuppressed(t *testing.T) {
	outcome := ApplyPreRules(models.FindingSuppressed, models.SeverityCritical, nil, nil)
	if !outcome.SkipAnalysis {
		t.Fatal("expected skip for suppressed finding")
	}
}

func TestApplyPreRules_SkipBelowSeverityThreshold(t *testing.T) {
	min := models.SeverityHigh
	outcome := ApplyPreRules(models.FindingOpen, models.SeverityMedium, nil, &min)
	if !outcome.SkipAnalysis {
		t.Fatal("expected skip for medium finding with high threshold")
	}
	if outcome.Reason == "" {
		t.Fatal("expected skip reason")
	}
}

func TestApplyPreRules_LowCVSSForcesReview(t *testing.T) {
	cvss := 2.5
	outcome := ApplyPreRules(models.FindingOpen, models.SeverityLow, &cvss, nil)
	if !outcome.ForceHumanReview {
		t.Fatal("expected human review for low CVSS")
	}
	if outcome.AdjustConfidenceCap == nil || *outcome.AdjustConfidenceCap != 0.6 {
		t.Fatal("expected confidence cap 0.6")
	}
}

func TestMergeWithLLM_LowSeverityConflict(t *testing.T) {
	llmResult := &llm.AnalysisResult{
		IsCritical:         true,
		IsExploitable:      true,
		CriticalityVerdict: "true_critical",
		Exploitability:     "high",
		Confidence:         0.9,
		Reasoning:          "remote code execution",
	}

	final := MergeWithLLM(RuleOutcome{}, llmResult, models.SeverityLow)
	if final.CriticalityVerdict != models.VerdictNeedsHumanReview {
		t.Fatalf("expected needs_human_review, got %s", final.CriticalityVerdict)
	}
}

func TestMergeWithLLM_PreRuleCapsConfidence(t *testing.T) {
	cap := 0.6
	pre := RuleOutcome{ForceHumanReview: true, AdjustConfidenceCap: &cap, Reason: "low cvss"}
	llmResult := &llm.AnalysisResult{
		CriticalityVerdict: "true_critical",
		Exploitability:     "medium",
		Confidence:         0.95,
		Reasoning:          "test",
	}

	final := MergeWithLLM(pre, llmResult, models.SeverityHigh)
	if final.Confidence != 0.6 {
		t.Fatalf("expected confidence 0.6, got %f", final.Confidence)
	}
	if final.CriticalityVerdict != models.VerdictNeedsHumanReview {
		t.Fatalf("expected needs_human_review, got %s", final.CriticalityVerdict)
	}
}
