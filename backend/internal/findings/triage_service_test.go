package findings

import (
	"testing"

	"github.com/purplehatlabs/Baldr/internal/models"
)

func TestEvaluateTriageFromAnalysis_AutoConfirm(t *testing.T) {
	result := EvaluateTriageFromAnalysis(TriageEvaluationInput{
		CriticalityVerdict: models.VerdictTrueCritical,
		ReachabilityStatus: models.ReachabilityReachable,
		Confidence:         0.85,
	})

	if result.Status != models.TriageConfirmed {
		t.Fatalf("expected confirmed, got %s", result.Status)
	}
	if !result.Auto {
		t.Fatal("expected auto confirmation")
	}
}

func TestEvaluateTriageFromAnalysis_NeedsReviewWhenNotReachable(t *testing.T) {
	result := EvaluateTriageFromAnalysis(TriageEvaluationInput{
		CriticalityVerdict: models.VerdictTrueCritical,
		ReachabilityStatus: models.ReachabilityUnknown,
		Confidence:         0.95,
	})

	if result.Status != models.TriageNeedsReview {
		t.Fatalf("expected needs_review, got %s", result.Status)
	}
}

func TestEvaluateTriageFromAnalysis_NeedsReviewLowConfidence(t *testing.T) {
	result := EvaluateTriageFromAnalysis(TriageEvaluationInput{
		CriticalityVerdict: models.VerdictTrueCritical,
		ReachabilityStatus: models.ReachabilityReachable,
		Confidence:         0.79,
	})

	if result.Status != models.TriageNeedsReview {
		t.Fatalf("expected needs_review, got %s", result.Status)
	}
}

func TestCanReopenTriage_AdminOnly(t *testing.T) {
	if err := CanReopenTriage(models.TriageDismissed, "member"); err != ErrTriageAdminRequired {
		t.Fatalf("expected admin required error, got %v", err)
	}
	if err := CanReopenTriage(models.TriageDismissed, "admin"); err != nil {
		t.Fatalf("expected admin allowed, got %v", err)
	}
}

func TestIsPendingTriage(t *testing.T) {
	if !IsPendingTriage(models.TriageNew) || !IsPendingTriage(models.TriageNeedsReview) {
		t.Fatal("expected pending triage statuses")
	}
	if IsPendingTriage(models.TriageConfirmed) {
		t.Fatal("confirmed should not be pending")
	}
}
