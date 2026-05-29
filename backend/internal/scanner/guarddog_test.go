package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalmodels "github.com/purplehatlabs/Baldr/internal/models"
)

func TestParseGuardDogSignalsExtractsJSONFromMixedOutput(t *testing.T) {
	t.Parallel()

	output := []byte("guarddog scanning...\n" +
		`{"results":[{"rule_id":"typosquat","confidence":0.85}]}` +
		"\nscan done")

	signals, err := parseGuardDogSignals(
		output,
		packageDependency{Name: "left-pad", Version: "1.0.0"},
		EcosystemNPM,
	)
	if err != nil {
		t.Fatalf("parseGuardDogSignals error: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	if signals[0].SignalKey != "typosquat" {
		t.Fatalf("unexpected signal key: %s", signals[0].SignalKey)
	}
	if signals[0].Severity != internalmodels.SeverityHigh {
		t.Fatalf("unexpected severity: %s", signals[0].Severity)
	}
	if signals[0].Confidence == nil {
		t.Fatal("expected confidence to be set")
	}
}

func TestGuardDogSeverityAndConfidenceMapping(t *testing.T) {
	t.Parallel()

	confidence := confidenceFromCandidate(map[string]any{"score": 80})
	if confidence == nil || *confidence != 0.8 {
		t.Fatalf("expected normalized confidence 0.8, got %v", confidence)
	}

	explicitSeverity := severityFromCandidate(
		map[string]any{"severity": "critical"},
		confidence,
	)
	if explicitSeverity != internalmodels.SeverityCritical {
		t.Fatalf("expected explicit critical severity, got %s", explicitSeverity)
	}

	inferredLow := severityFromCandidate(map[string]any{}, ptrFloat(0.49))
	if inferredLow != internalmodels.SeverityLow {
		t.Fatalf("expected low severity, got %s", inferredLow)
	}
	inferredMedium := severityFromCandidate(map[string]any{}, ptrFloat(0.50))
	if inferredMedium != internalmodels.SeverityMedium {
		t.Fatalf("expected medium severity, got %s", inferredMedium)
	}
	inferredHigh := severityFromCandidate(map[string]any{}, ptrFloat(0.75))
	if inferredHigh != internalmodels.SeverityHigh {
		t.Fatalf("expected high severity, got %s", inferredHigh)
	}
	inferredCritical := severityFromCandidate(map[string]any{}, ptrFloat(0.90))
	if inferredCritical != internalmodels.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", inferredCritical)
	}
}

func TestScanManifestGuardDogFailSoftAcrossDependencies(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	requirementsPath := filepath.Join(tempDir, "requirements.txt")
	requirementsContent := "badpkg==1.0.0\ngoodpkg==2.0.0\n"
	if err := os.WriteFile(requirementsPath, []byte(requirementsContent), 0o600); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}

	binaryPath := filepath.Join(tempDir, "guarddog-mock.sh")
	script := `#!/bin/sh
pkg="$3"
if [ "$pkg" = "badpkg" ]; then
  echo "not-json"
  exit 1
fi
if [ "$pkg" = "goodpkg" ]; then
  echo '{"rule_id":"install_script","confidence":0.95}'
  exit 0
fi
echo '[]'
exit 0
`
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write mock guarddog binary: %v", err)
	}

	signals, err := ScanManifestGuardDog(
		context.Background(),
		Manifest{
			Path:      "requirements.txt",
			AbsPath:   requirementsPath,
			Ecosystem: EcosystemPyPI,
		},
		GuardDogOptions{
			BinaryPath: binaryPath,
			Timeout:    5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("ScanManifestGuardDog error: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal from successful dependency, got %d", len(signals))
	}
	if signals[0].PackageName != "goodpkg" {
		t.Fatalf("unexpected package name: %s", signals[0].PackageName)
	}
	if signals[0].Severity != internalmodels.SeverityCritical {
		t.Fatalf("unexpected severity: %s", signals[0].Severity)
	}
}

func ptrFloat(v float64) *float64 {
	return &v
}
