package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/google/uuid"
	internalmodels "github.com/purplehatlabs/Baldr/internal/models"
)

// ScanResult groups findings from a single manifest file.
type ScanResult struct {
	Manifest Manifest
	Findings []internalmodels.Finding
}

// ScanManifest runs osv-scanner against a single manifest file and returns findings.
func ScanManifest(_ context.Context, manifest Manifest) ([]internalmodels.Finding, error) {
	actions := osvscanner.ScannerActions{
		LockfilePaths: []string{manifest.AbsPath},
	}

	results, err := osvscanner.DoScan(actions, nil)
	if err != nil && !isErrVulnsFound(err) {
		return nil, fmt.Errorf("osv-scanner scan %s: %w", manifest.Path, err)
	}

	return mapResults(results, manifest), nil
}

// ScanRepo scans all manifests in a repository directory.
func ScanRepo(ctx context.Context, repoRoot string) ([]ScanResult, error) {
	manifests, err := FindManifests(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("find manifests: %w", err)
	}

	var results []ScanResult
	for _, m := range manifests {
		findings, err := ScanManifest(ctx, m)
		if err != nil {
			// One bad manifest should not abort the whole scan
			continue
		}
		results = append(results, ScanResult{Manifest: m, Findings: findings})
	}
	return results, nil
}

// mapResults converts osv-scanner output to internal Finding models.
func mapResults(results models.VulnerabilityResults, manifest Manifest) []internalmodels.Finding {
	var findings []internalmodels.Finding
	_ = manifest // manifest context used by caller

	for _, sourceResult := range results.Results {
		for _, pkg := range sourceResult.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				severity, cvss := classifySeverity(vuln)

				finding := internalmodels.Finding{
					ID:             uuid.New(),
					OSVID:          vuln.ID,
					PackageName:    pkg.Package.Name,
					PackageVersion: pkg.Package.Version,
					Severity:       severity,
					CVSSScore:      cvss,
					Summary:        vuln.Summary,
					Details:        vuln.Details,
					Status:         internalmodels.FindingOpen,
					FirstSeenAt:    time.Now(),
					LastSeenAt:     time.Now(),
				}

				for _, affected := range vuln.Affected {
					for _, r := range affected.Ranges {
						for _, event := range r.Events {
							if event.Fixed != "" {
								v := event.Fixed
								finding.FixedVersion = &v
								goto nextAffected
							}
						}
					}
				nextAffected:
				}

				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func isErrVulnsFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "vulnerabilities found")
}
