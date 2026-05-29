package scanner

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// Ecosystem identifiers matching OSV/osv-scanner conventions.
const (
	EcosystemGo       = "Go"
	EcosystemNPM      = "npm"
	EcosystemPyPI     = "PyPI"
	EcosystemMaven    = "Maven"
	EcosystemCargo    = "crates.io"
	EcosystemRubyGems = "RubyGems"
	EcosystemNuGet    = "NuGet"
	EcosystemComposer = "Packagist"
)

// manifestFile maps a lock/manifest filename to its ecosystem.
// osv-scanner uses these files directly for scanning.
var manifestFiles = map[string]string{
	// Go
	"go.mod": EcosystemGo,
	"go.sum": EcosystemGo,
	// Node.js
	"package-lock.json": EcosystemNPM,
	"yarn.lock":         EcosystemNPM,
	"pnpm-lock.yaml":    EcosystemNPM,
	// Python
	"requirements.txt": EcosystemPyPI,
	"Pipfile.lock":     EcosystemPyPI,
	"poetry.lock":      EcosystemPyPI,
	"pyproject.toml":   EcosystemPyPI,
	// Java/Kotlin
	"pom.xml":          EcosystemMaven,
	"build.gradle":     EcosystemMaven,
	"build.gradle.kts": EcosystemMaven,
	// Rust
	"Cargo.lock": EcosystemCargo,
	// Ruby
	"Gemfile.lock": EcosystemRubyGems,
	// .NET
	"packages.lock.json": EcosystemNuGet,
	// PHP
	"composer.lock": EcosystemComposer,
}

// skipDirs are directory names that should never be scanned.
var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	".svn":         true,
	"__pycache__":  true,
	".tox":         true,
	"dist":         true,
	"build":        true,
	"target":       true, // Maven/Rust build output
	".gradle":      true,
	"coverage":     true,
	".nyc_output":  true,
	"testdata":     true,
}

// Manifest represents a discovered dependency manifest within a repository.
type Manifest struct {
	// Path is relative to the repository root.
	Path string
	// AbsPath is the absolute filesystem path.
	AbsPath   string
	Ecosystem string
}

// FindManifests walks repoRoot recursively and returns all discovered manifests.
// It skips common non-source directories and detects monorepos automatically.
func FindManifests(repoRoot string) ([]Manifest, error) {
	var manifests []Manifest

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}

		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		eco, ok := manifestFiles[d.Name()]
		if !ok {
			return nil
		}

		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return nil
		}

		manifests = append(manifests, Manifest{
			Path:      rel,
			AbsPath:   path,
			Ecosystem: eco,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Deduplicate: if both go.mod and go.sum exist in the same directory,
	// prefer go.mod (osv-scanner handles it better).
	return deduplicateGoManifests(manifests), nil
}

// IsMonorepo returns true when manifests span multiple distinct directories.
func IsMonorepo(manifests []Manifest) bool {
	dirs := map[string]bool{}
	for _, m := range manifests {
		dirs[filepath.Dir(m.Path)] = true
	}
	return len(dirs) > 1
}

// deduplicateGoManifests removes go.sum when go.mod exists in the same dir.
func deduplicateGoManifests(manifests []Manifest) []Manifest {
	goModDirs := map[string]bool{}
	for _, m := range manifests {
		if strings.HasSuffix(m.Path, "go.mod") {
			goModDirs[filepath.Dir(m.Path)] = true
		}
	}

	result := make([]Manifest, 0, len(manifests))
	for _, m := range manifests {
		if strings.HasSuffix(m.Path, "go.sum") && goModDirs[filepath.Dir(m.Path)] {
			continue
		}
		result = append(result, m)
	}
	return result
}
