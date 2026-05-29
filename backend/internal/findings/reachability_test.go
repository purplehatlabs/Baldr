package findings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/purplehatlabs/Baldr/internal/models"
	"github.com/purplehatlabs/Baldr/internal/scanner"
)

func TestAnalyzeReachability_GoImport(t *testing.T) {
	dir := t.TempDir()
	modDir := filepath.Join(dir, "services", "api")
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

	result := AnalyzeReachability(dir, scanner.Manifest{
		Path:      "services/api/go.mod",
		Ecosystem: scanner.EcosystemGo,
	}, "github.com/gin-gonic/gin")

	if result.Status != models.ReachabilityReachable {
		t.Fatalf("expected reachable, got %s", result.Status)
	}
}

func TestAnalyzeReachability_NPMUnreachable(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(`{"dependencies":{"lodash":{"version":"4.17.21"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	result := AnalyzeReachability(dir, scanner.Manifest{
		Path:      "package-lock.json",
		Ecosystem: scanner.EcosystemNPM,
	}, "left-pad")

	if result.Status != models.ReachabilityUnreachable {
		t.Fatalf("expected unreachable, got %s", result.Status)
	}
}

func TestAnalyzeReachability_UnsupportedEcosystem(t *testing.T) {
	result := AnalyzeReachability(t.TempDir(), scanner.Manifest{
		Path:      "pom.xml",
		Ecosystem: scanner.EcosystemMaven,
	}, "org.apache.commons:commons-lang3")

	if result.Status != models.ReachabilityUnknown {
		t.Fatalf("expected unknown, got %s", result.Status)
	}
}
