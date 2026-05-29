package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	internalmodels "github.com/purplehatlabs/Baldr/internal/models"
)

var ErrGuardDogUnsupportedManifest = errors.New("guarddog unsupported manifest")

type GuardDogOptions struct {
	BinaryPath string
	Timeout    time.Duration
}

type SupplyChainSignal struct {
	SignalKey      string
	Severity       internalmodels.Severity
	Confidence     *float64
	EvidenceJSON   []byte
	PackageName    string
	PackageVersion string
	Ecosystem      string
}

type packageDependency struct {
	Name    string
	Version string
}

type ParsedDependency struct {
	Name    string
	Version string
}

func SupportsGuardDogManifest(manifest Manifest) bool {
	switch strings.ToLower(filepath.Base(manifest.Path)) {
	case "package-lock.json", "requirements.txt", "pipfile.lock":
		return true
	default:
		return false
	}
}

func ScanManifestGuardDog(ctx context.Context, manifest Manifest, opts GuardDogOptions) ([]SupplyChainSignal, error) {
	if opts.BinaryPath == "" {
		opts.BinaryPath = "guarddog"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Minute
	}

	dependencies, err := dependenciesForGuardDogManifest(manifest)
	if err != nil {
		return nil, err
	}
	if len(dependencies) == 0 {
		return nil, nil
	}

	signals := make([]SupplyChainSignal, 0)
	for _, dep := range dependencies {
		depSignals, err := scanGuardDogDependency(ctx, manifest.Ecosystem, dep, opts)
		if err != nil {
			continue
		}
		signals = append(signals, depSignals...)
	}
	return dedupeSignals(signals), nil
}

func ParseManifestDependencies(manifest Manifest) ([]ParsedDependency, error) {
	dependencies, err := dependenciesForGuardDogManifest(manifest)
	if err != nil {
		return nil, err
	}
	out := make([]ParsedDependency, 0, len(dependencies))
	for _, dependency := range dependencies {
		out = append(out, ParsedDependency{
			Name:    dependency.Name,
			Version: dependency.Version,
		})
	}
	return out, nil
}

func dependenciesForGuardDogManifest(manifest Manifest) ([]packageDependency, error) {
	if !SupportsGuardDogManifest(manifest) {
		return nil, ErrGuardDogUnsupportedManifest
	}

	switch strings.ToLower(filepath.Base(manifest.Path)) {
	case "package-lock.json":
		return parsePackageLockDependencies(manifest.AbsPath)
	case "requirements.txt":
		return parseRequirementsDependencies(manifest.AbsPath)
	case "pipfile.lock":
		return parsePipfileLockDependencies(manifest.AbsPath)
	default:
		return nil, ErrGuardDogUnsupportedManifest
	}
}

func scanGuardDogDependency(
	ctx context.Context,
	ecosystem string,
	dependency packageDependency,
	opts GuardDogOptions,
) ([]SupplyChainSignal, error) {
	guardDogEcosystem, err := guardDogEcosystemFromManifestEcosystem(ecosystem)
	if err != nil {
		return nil, err
	}

	args := []string{guardDogEcosystem, "scan", dependency.Name, "--output-format=json"}
	if dependency.Version != "" {
		args = append(args, "--version", dependency.Version)
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, opts.BinaryPath, args...)
	output, runErr := cmd.CombinedOutput()

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("guarddog timeout package %s@%s", dependency.Name, dependency.Version)
	}

	signals, parseErr := parseGuardDogSignals(output, dependency, ecosystem)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("guarddog command failed (%w) and parse failed: %v", runErr, parseErr)
		}
		return nil, parseErr
	}
	if runErr != nil && len(signals) == 0 {
		return nil, fmt.Errorf("guarddog command failed: %w", runErr)
	}

	return signals, nil
}

func guardDogEcosystemFromManifestEcosystem(ecosystem string) (string, error) {
	switch ecosystem {
	case EcosystemNPM:
		return "npm", nil
	case EcosystemPyPI:
		return "pypi", nil
	default:
		return "", fmt.Errorf("unsupported ecosystem for guarddog: %s", ecosystem)
	}
}

func parseGuardDogSignals(
	output []byte,
	dependency packageDependency,
	ecosystem string,
) ([]SupplyChainSignal, error) {
	rawJSON, ok := extractJSONObjectOrArray(output)
	if !ok {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("guarddog output is not json")
	}

	var payload any
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal guarddog output: %w", err)
	}

	candidates := make([]map[string]any, 0)
	collectSignalCandidates(payload, &candidates)
	if len(candidates) == 0 {
		return nil, nil
	}

	signals := make([]SupplyChainSignal, 0, len(candidates))
	for _, candidate := range candidates {
		signalKey := signalKeyFromCandidate(candidate)
		if signalKey == "" {
			continue
		}

		evidenceJSON, err := json.Marshal(candidate)
		if err != nil {
			evidenceJSON = []byte("{}")
		}

		confidence := confidenceFromCandidate(candidate)
		severity := severityFromCandidate(candidate, confidence)

		signals = append(signals, SupplyChainSignal{
			SignalKey:      signalKey,
			Severity:       severity,
			Confidence:     confidence,
			EvidenceJSON:   evidenceJSON,
			PackageName:    dependency.Name,
			PackageVersion: dependency.Version,
			Ecosystem:      ecosystem,
		})
	}

	return signals, nil
}

func extractJSONObjectOrArray(raw []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false
	}

	if trimmed[0] == '{' || trimmed[0] == '[' {
		return trimmed, true
	}

	objectStart := bytes.IndexByte(trimmed, '{')
	objectEnd := bytes.LastIndexByte(trimmed, '}')
	arrayStart := bytes.IndexByte(trimmed, '[')
	arrayEnd := bytes.LastIndexByte(trimmed, ']')

	switch {
	case objectStart >= 0 && objectEnd > objectStart:
		return trimmed[objectStart : objectEnd+1], true
	case arrayStart >= 0 && arrayEnd > arrayStart:
		return trimmed[arrayStart : arrayEnd+1], true
	default:
		return nil, false
	}
}

func collectSignalCandidates(value any, out *[]map[string]any) {
	switch v := value.(type) {
	case map[string]any:
		if looksLikeSignal(v) {
			*out = append(*out, v)
		}
		for _, child := range v {
			collectSignalCandidates(child, out)
		}
	case []any:
		for _, child := range v {
			collectSignalCandidates(child, out)
		}
	}
}

func looksLikeSignal(candidate map[string]any) bool {
	keys := []string{"rule", "rule_id", "id", "name", "check_id", "description", "message"}
	for _, key := range keys {
		if str, ok := candidate[key].(string); ok && strings.TrimSpace(str) != "" {
			return true
		}
	}
	return false
}

func signalKeyFromCandidate(candidate map[string]any) string {
	for _, key := range []string{"rule_id", "rule", "check_id", "id", "name"} {
		if str, ok := candidate[key].(string); ok {
			str = strings.TrimSpace(str)
			if str != "" {
				return strings.ToLower(strings.ReplaceAll(str, " ", "_"))
			}
		}
	}
	return ""
}

func confidenceFromCandidate(candidate map[string]any) *float64 {
	for _, key := range []string{"confidence", "score"} {
		raw, ok := candidate[key]
		if !ok {
			continue
		}
		value, ok := toFloat64(raw)
		if !ok {
			continue
		}
		if value > 1 {
			value = value / 100
		}
		if value < 0 {
			value = 0
		}
		if value > 1 {
			value = 1
		}
		return &value
	}
	return nil
}

func severityFromCandidate(candidate map[string]any, confidence *float64) internalmodels.Severity {
	if rawSeverity, ok := candidate["severity"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(rawSeverity)) {
		case string(internalmodels.SeverityCritical):
			return internalmodels.SeverityCritical
		case string(internalmodels.SeverityHigh):
			return internalmodels.SeverityHigh
		case string(internalmodels.SeverityMedium):
			return internalmodels.SeverityMedium
		case string(internalmodels.SeverityLow):
			return internalmodels.SeverityLow
		}
	}
	if confidence == nil {
		return internalmodels.SeverityMedium
	}
	switch {
	case *confidence >= 0.9:
		return internalmodels.SeverityCritical
	case *confidence >= 0.75:
		return internalmodels.SeverityHigh
	case *confidence >= 0.5:
		return internalmodels.SeverityMedium
	default:
		return internalmodels.SeverityLow
	}
}

func parsePackageLockDependencies(path string) ([]packageDependency, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package-lock: %w", err)
	}

	type packageLockDependency struct {
		Version      string                           `json:"version"`
		Dependencies map[string]packageLockDependency `json:"dependencies"`
	}
	type packageLock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]packageLockDependency `json:"dependencies"`
	}

	var lock packageLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock json: %w", err)
	}

	unique := map[string]packageDependency{}
	addDependency := func(name, version string) {
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" || version == "" {
			return
		}
		key := name + "@" + version
		unique[key] = packageDependency{Name: name, Version: version}
	}

	for pathKey, pkg := range lock.Packages {
		if pathKey == "" {
			continue
		}
		name := strings.TrimSpace(pkg.Name)
		if name == "" {
			name = packageNameFromNodeModulesPath(pathKey)
		}
		addDependency(name, pkg.Version)
	}

	var walkDependencies func(dependencies map[string]packageLockDependency)
	walkDependencies = func(dependencies map[string]packageLockDependency) {
		for name, dependency := range dependencies {
			addDependency(name, dependency.Version)
			if len(dependency.Dependencies) > 0 {
				walkDependencies(dependency.Dependencies)
			}
		}
	}
	if len(lock.Dependencies) > 0 {
		walkDependencies(lock.Dependencies)
	}

	return toSortedDependencies(unique), nil
}

func packageNameFromNodeModulesPath(path string) string {
	const marker = "node_modules/"
	index := strings.LastIndex(path, marker)
	if index < 0 {
		return ""
	}
	name := path[index+len(marker):]
	if strings.Contains(name, "/node_modules/") {
		return packageNameFromNodeModulesPath(name)
	}
	return strings.TrimSpace(name)
}

func parseRequirementsDependencies(path string) ([]packageDependency, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read requirements.txt: %w", err)
	}

	lines := strings.Split(string(raw), "\n")
	unique := map[string]packageDependency{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}

		if semicolon := strings.Index(line, ";"); semicolon >= 0 {
			line = strings.TrimSpace(line[:semicolon])
		}

		name, version := splitRequirementLine(line)
		if name == "" {
			continue
		}
		key := name + "@" + version
		unique[key] = packageDependency{Name: name, Version: version}
	}

	return toSortedDependencies(unique), nil
}

func splitRequirementLine(line string) (string, string) {
	separators := []string{"==", "~=", ">=", "<=", "!=", ">", "<"}
	for _, separator := range separators {
		parts := strings.SplitN(line, separator, 2)
		if len(parts) != 2 {
			continue
		}
		name := normalizePythonPackageName(parts[0])
		version := strings.TrimSpace(parts[1])
		return name, version
	}
	return normalizePythonPackageName(line), ""
}

func normalizePythonPackageName(name string) string {
	name = strings.TrimSpace(name)
	if extrasIndex := strings.Index(name, "["); extrasIndex >= 0 {
		name = strings.TrimSpace(name[:extrasIndex])
	}
	return name
}

func parsePipfileLockDependencies(path string) ([]packageDependency, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock json: %w", err)
	}

	unique := map[string]packageDependency{}
	for _, sectionName := range []string{"default", "develop"} {
		sectionValue, ok := payload[sectionName]
		if !ok {
			continue
		}
		sectionMap, ok := sectionValue.(map[string]any)
		if !ok {
			continue
		}
		for packageName, metadataValue := range sectionMap {
			metadata, ok := metadataValue.(map[string]any)
			if !ok {
				continue
			}
			versionRaw, _ := metadata["version"].(string)
			version := strings.TrimSpace(versionRaw)
			version = strings.TrimLeft(version, "=<>!~")

			normalizedName := normalizePythonPackageName(packageName)
			key := normalizedName + "@" + version
			unique[key] = packageDependency{Name: normalizedName, Version: version}
		}
	}

	return toSortedDependencies(unique), nil
}

func toSortedDependencies(unique map[string]packageDependency) []packageDependency {
	dependencies := make([]packageDependency, 0, len(unique))
	for _, dependency := range unique {
		dependencies = append(dependencies, dependency)
	}
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Name == dependencies[j].Name {
			return dependencies[i].Version < dependencies[j].Version
		}
		return dependencies[i].Name < dependencies[j].Name
	})
	return dependencies
}

func dedupeSignals(signals []SupplyChainSignal) []SupplyChainSignal {
	unique := make(map[string]SupplyChainSignal, len(signals))
	for _, signal := range signals {
		key := strings.Join([]string{
			signal.Ecosystem,
			signal.PackageName,
			signal.PackageVersion,
			signal.SignalKey,
		}, "|")
		unique[key] = signal
	}

	deduped := make([]SupplyChainSignal, 0, len(unique))
	for _, signal := range unique {
		deduped = append(deduped, signal)
	}
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].PackageName == deduped[j].PackageName {
			if deduped[i].PackageVersion == deduped[j].PackageVersion {
				return deduped[i].SignalKey < deduped[j].SignalKey
			}
			return deduped[i].PackageVersion < deduped[j].PackageVersion
		}
		return deduped[i].PackageName < deduped[j].PackageName
	})
	return deduped
}

func toFloat64(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
