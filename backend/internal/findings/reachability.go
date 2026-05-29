package findings

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/purplehatlabs/Baldr/internal/models"
	"github.com/purplehatlabs/Baldr/internal/scanner"
)

type ReachabilityEvidence struct {
	Method      string   `json:"method"`
	Ecosystem   string   `json:"ecosystem"`
	PackageName string   `json:"package_name"`
	MatchedIn   []string `json:"matched_in,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

type ReachabilityResult struct {
	Status     models.ReachabilityStatus
	Confidence float64
	Evidence   ReachabilityEvidence
}

// AnalyzeReachability performs dependency-level reachability heuristics for v1.
func AnalyzeReachability(
	repoRoot string,
	manifest scanner.Manifest,
	packageName string,
) ReachabilityResult {
	evidence := ReachabilityEvidence{
		Ecosystem:   manifest.Ecosystem,
		PackageName: packageName,
	}

	switch manifest.Ecosystem {
	case scanner.EcosystemGo:
		return analyzeGoReachability(repoRoot, manifest, packageName, evidence)
	case scanner.EcosystemNPM:
		return analyzeNPMReachability(repoRoot, manifest, packageName, evidence)
	case scanner.EcosystemPyPI:
		return analyzePyPIReachability(repoRoot, manifest, packageName, evidence)
	default:
		evidence.Method = "fallback"
		evidence.Reason = "ecosystem not supported in reachability v1"
		return ReachabilityResult{
			Status:     models.ReachabilityUnknown,
			Confidence: 0.3,
			Evidence:   evidence,
		}
	}
}

func analyzeGoReachability(
	repoRoot string,
	manifest scanner.Manifest,
	packageName string,
	evidence ReachabilityEvidence,
) ReachabilityResult {
	evidence.Method = "go_module_import"
	matched := []string{}

	modPath := filepath.Join(repoRoot, filepath.Dir(manifest.Path), "go.mod")
	if manifest.Path == "go.mod" {
		modPath = filepath.Join(repoRoot, "go.mod")
	}

	if content, err := os.ReadFile(modPath); err == nil {
		modText := string(content)
		if strings.Contains(modText, packageName) {
			matched = append(matched, filepath.Base(modPath))
		}
	}

	importNeedle := `"` + packageName + `"`
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, string(os.PathSeparator)+"vendor"+string(os.PathSeparator)) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.Contains(string(content), importNeedle) {
			rel, _ := filepath.Rel(repoRoot, path)
			matched = append(matched, rel)
		}
		return nil
	})
	_ = err

	if len(matched) > 0 {
		evidence.MatchedIn = matched
		return ReachabilityResult{
			Status:     models.ReachabilityReachable,
			Confidence: 0.75,
			Evidence:   evidence,
		}
	}

	evidence.Reason = "package not referenced in go.mod or Go imports"
	return ReachabilityResult{
		Status:     models.ReachabilityUnreachable,
		Confidence: 0.6,
		Evidence:   evidence,
	}
}

func analyzeNPMReachability(
	repoRoot string,
	manifest scanner.Manifest,
	packageName string,
	evidence ReachabilityEvidence,
) ReachabilityResult {
	evidence.Method = "npm_lockfile"
	matched := []string{}

	lockCandidates := []string{
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "package-lock.json"),
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "yarn.lock"),
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "pnpm-lock.yaml"),
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "package.json"),
	}
	if manifest.Path != "" {
		lockCandidates = append([]string{filepath.Join(repoRoot, manifest.Path)}, lockCandidates...)
	}

	for _, candidate := range lockCandidates {
		content, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		if lockfileReferencesPackage(string(content), packageName) {
			rel, _ := filepath.Rel(repoRoot, candidate)
			matched = append(matched, rel)
		}
	}

	if len(matched) > 0 {
		evidence.MatchedIn = matched
		return ReachabilityResult{
			Status:     models.ReachabilityReachable,
			Confidence: 0.7,
			Evidence:   evidence,
		}
	}

	evidence.Reason = "package not found in npm lockfiles or package.json"
	return ReachabilityResult{
		Status:     models.ReachabilityUnreachable,
		Confidence: 0.55,
		Evidence:   evidence,
	}
}

func analyzePyPIReachability(
	repoRoot string,
	manifest scanner.Manifest,
	packageName string,
	evidence ReachabilityEvidence,
) ReachabilityResult {
	evidence.Method = "python_requirements"
	matched := []string{}
	normalized := normalizePyPackageName(packageName)

	candidates := []string{
		filepath.Join(repoRoot, manifest.Path),
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "requirements.txt"),
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "pyproject.toml"),
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "poetry.lock"),
		filepath.Join(repoRoot, filepath.Dir(manifest.Path), "Pipfile.lock"),
	}

	for _, candidate := range candidates {
		content, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		if pythonManifestReferencesPackage(string(content), normalized) {
			rel, _ := filepath.Rel(repoRoot, candidate)
			matched = append(matched, rel)
		}
	}

	importHits := findPythonImportHits(repoRoot, normalized)
	matched = append(matched, importHits...)

	if len(matched) > 0 {
		evidence.MatchedIn = matched
		return ReachabilityResult{
			Status:     models.ReachabilityReachable,
			Confidence: 0.65,
			Evidence:   evidence,
		}
	}

	evidence.Reason = "package not found in python manifests or imports"
	return ReachabilityResult{
		Status:     models.ReachabilityUnreachable,
		Confidence: 0.5,
		Evidence:   evidence,
	}
}

func lockfileReferencesPackage(content, packageName string) bool {
	needles := []string{
		`"` + packageName + `"`,
		`"` + packageName + `@`,
		" " + packageName + "@",
		`"` + packageName + `":`,
	}
	for _, needle := range needles {
		if strings.Contains(content, needle) {
			return true
		}
	}
	return false
}

func normalizePyPackageName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "-", "_"))
}

func pythonManifestReferencesPackage(content, normalizedName string) bool {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.Split(line, "#")[0])
		if trimmed == "" {
			continue
		}
		base := strings.Split(trimmed, "==")[0]
		base = strings.Split(base, ">=")[0]
		base = strings.Split(base, "[")[0]
		base = strings.TrimSpace(base)
		if normalizePyPackageName(base) == normalizedName {
			return true
		}
	}
	return strings.Contains(strings.ToLower(content), normalizedName)
}

func findPythonImportHits(repoRoot, normalizedName string) []string {
	matched := []string{}
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".py") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "import "+normalizedName) ||
				strings.HasPrefix(line, "from "+normalizedName+" ") {
				rel, _ := filepath.Rel(repoRoot, path)
				matched = append(matched, rel)
				break
			}
		}
		return nil
	})
	return matched
}

func ReachabilityAnalyzedAtNow() time.Time {
	return time.Now().UTC()
}

func MarshalReachabilityEvidence(evidence ReachabilityEvidence) ([]byte, error) {
	return json.Marshal(evidence)
}
