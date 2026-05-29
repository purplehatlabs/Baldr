package findings

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/purplehatlabs/Baldr/internal/models"
	"github.com/purplehatlabs/Baldr/internal/scanner"
)

func TestPrioritizationFlow_ReachableIncreasesRiskScore(t *testing.T) {
	dir := t.TempDir()
	modDir := filepath.Join(dir, "cmd", "api")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "go.mod"), []byte("module example.com/api\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "main.go"), []byte(`package main
import "github.com/gin-gonic/gin"
func main() { _ = gin.H{} }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	reach := AnalyzeReachability(dir, scanner.Manifest{
		Path:      "cmd/api/go.mod",
		Ecosystem: scanner.EcosystemGo,
	}, "github.com/gin-gonic/gin")
	if reach.Status != models.ReachabilityReachable {
		t.Fatalf("expected reachable, got %s", reach.Status)
	}

	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-24 * time.Hour)
	base := RiskScoreInput{
		Severity:           models.SeverityHigh,
		Status:             models.FindingOpen,
		FirstSeenAt:        firstSeen,
		ReachabilityStatus: models.ReachabilityUnknown,
	}
	reachable := base
	reachable.ReachabilityStatus = reach.Status
	reachable.ReachabilityConfidence = &reach.Confidence

	reachableScore := CalculateRiskScore(reachable, now)
	unknownScore := CalculateRiskScore(base, now)

	if reachableScore.Score <= unknownScore.Score {
		t.Fatalf("reachable score (%f) should exceed unknown score (%f)", reachableScore.Score, unknownScore.Score)
	}
	if reachableScore.Tier == models.RiskTierLow {
		t.Fatalf("expected non-low tier for reachable high severity finding, got %s", reachableScore.Tier)
	}
}
