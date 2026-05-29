package codeagent

import (
	"path/filepath"
	"strings"
)

// PrepareImportSitesForAgent filters noisy reachability paths and caps how many
// sites are exposed to the LLM agent (bootstrap prompt + list_import_sites tool).
func PrepareImportSitesForAgent(sites []string) (prepared []string, total int, omitted int) {
	total = len(sites)
	if total == 0 {
		return nil, 0, 0
	}

	filtered := make([]string, 0, len(sites))
	deprioritized := make([]string, 0)

	for _, site := range sites {
		site = strings.TrimSpace(site)
		if site == "" || isLockOrManifestPath(site) {
			continue
		}
		if isDeprioritizedImportPath(site) {
			deprioritized = append(deprioritized, site)
			continue
		}
		filtered = append(filtered, site)
	}
	filtered = append(filtered, deprioritized...)

	if len(filtered) > MaxImportSites {
		prepared = append([]string(nil), filtered[:MaxImportSites]...)
		omitted = len(filtered) - MaxImportSites
		return prepared, total, omitted
	}
	return filtered, total, 0
}

func isLockOrManifestPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "poetry.lock", "pipfile.lock", "pipfile", "pyproject.toml", "requirements.txt",
		"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum",
		"gemfile.lock", "composer.lock", "cargo.lock":
		return true
	}
	return false
}

func isDeprioritizedImportPath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.Contains(normalized, "/tests/"),
		strings.HasPrefix(normalized, "tests/"),
		strings.Contains(normalized, "/test/"),
		strings.HasPrefix(normalized, "test/"),
		strings.Contains(normalized, "/__tests__/"),
		strings.Contains(normalized, "/migrations/"),
		strings.HasPrefix(normalized, "migrations/"),
		strings.Contains(normalized, "/__pycache__/"),
		strings.HasSuffix(normalized, "_test.go"),
		strings.HasSuffix(normalized, "_test.py"),
		strings.HasSuffix(normalized, ".test.js"),
		strings.HasSuffix(normalized, ".test.ts"),
		strings.HasSuffix(normalized, ".spec.js"),
		strings.HasSuffix(normalized, ".spec.ts"):
		return true
	}
	return false
}
