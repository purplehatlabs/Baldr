package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/purplehatlabs/Baldr/internal/findings/codeagent"
	"github.com/purplehatlabs/Baldr/internal/models"
)

type AnalysisContext struct {
	FindingContextRow
	RepoID                 uuid.UUID
	DefaultBranch          string
	InstallationID         int64
	ReachabilityStatus     models.ReachabilityStatus
	ReachabilityConfidence *float64
	ImportSites            []string
	IsInternetExposed      *bool
	AssetCriticality       string
	DataSensitivity        string
	Environment            string
}

func (s *Service) LoadAnalysisContext(ctx context.Context, findingID, tenantID uuid.UUID) (*AnalysisContext, error) {
	row, err := s.LoadFindingContext(ctx, findingID, tenantID)
	if err != nil {
		return nil, err
	}

	var (
		repoID           uuid.UUID
		defaultBranch    string
		installationID   int64
		reachStatus      models.ReachabilityStatus
		reachConf        *float64
		reachEvidenceRaw []byte
		isInternet       *bool
		assetCriticality string
		dataSensitivity  string
		environment      string
	)

	err = s.db.QueryRow(ctx, `
		SELECT r.id, COALESCE(r.default_branch, 'main'), o.github_app_installation_id,
		       f.reachability_status, f.reachability_confidence, f.reachability_evidence_json,
		       r.is_internet_exposed,
		       COALESCE(r.asset_criticality, 'medium'),
		       COALESCE(r.data_sensitivity, 'internal'),
		       COALESCE(r.environment, 'prod')
		FROM findings f
		JOIN manifests m ON m.id = f.manifest_id
		JOIN repositories r ON r.id = m.repo_id
		JOIN organizations o ON o.id = r.org_id
		WHERE f.id = $1 AND o.tenant_id = $2`,
		findingID, tenantID,
	).Scan(
		&repoID, &defaultBranch, &installationID,
		&reachStatus, &reachConf, &reachEvidenceRaw,
		&isInternet, &assetCriticality, &dataSensitivity, &environment,
	)
	if err != nil {
		return nil, fmt.Errorf("load analysis context: %w", err)
	}

	importSites := parseImportSites(reachEvidenceRaw)

	return &AnalysisContext{
		FindingContextRow:      *row,
		RepoID:                 repoID,
		DefaultBranch:          defaultBranch,
		InstallationID:         installationID,
		ReachabilityStatus:     reachStatus,
		ReachabilityConfidence: reachConf,
		ImportSites:            importSites,
		IsInternetExposed:      isInternet,
		AssetCriticality:       assetCriticality,
		DataSensitivity:        dataSensitivity,
		Environment:            environment,
	}, nil
}

func parseImportSites(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var evidence struct {
		MatchedIn []string `json:"matched_in"`
	}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return nil
	}
	return evidence.MatchedIn
}

func (s *Service) resolveRepoClone(ctx context.Context, actx *AnalysisContext) (string, func(), error) {
	if s.github == nil {
		return "", func() {}, fmt.Errorf("github client not configured for code analysis")
	}
	if cached, ok := globalCloneCache.Get(actx.RepoID); ok {
		return cached, func() {}, nil
	}

	parts := strings.SplitN(actx.RepoName, "/", 2)
	if len(parts) != 2 {
		return "", func() {}, fmt.Errorf("invalid repo full_name: %s", actx.RepoName)
	}

	cloneDir, err := s.github.CloneRepo(
		ctx,
		actx.TenantID,
		actx.InstallationID,
		parts[0],
		parts[1],
		actx.DefaultBranch,
		analysisWorkDir(),
	)
	if err != nil {
		return "", func() {}, err
	}

	cleanup := func() {
		globalCloneCache.Release(actx.RepoID, cloneDir, true)
	}
	return cloneDir, cleanup, nil
}

func buildCodeAgentBootstrap(actx *AnalysisContext) codeagent.BootstrapContext {
	fixed := ""
	if actx.Finding.FixedVersion != nil {
		fixed = *actx.Finding.FixedVersion
	}
	cvss := "unknown"
	if actx.Finding.CVSSScore != nil {
		cvss = fmt.Sprintf("%.1f", *actx.Finding.CVSSScore)
	}
	importSites, total, omitted := codeagent.PrepareImportSitesForAgent(actx.ImportSites)
	searchHints := codeagent.ExtractAdvisorySearchHints(actx.Finding.Summary, actx.Finding.Details)
	return codeagent.BootstrapContext{
		OSVID:                  actx.Finding.OSVID,
		PackageName:            actx.Finding.PackageName,
		PackageVersion:         actx.Finding.PackageVersion,
		FixedVersion:           fixed,
		Severity:               string(actx.Finding.Severity),
		CVSSScore:              cvss,
		Summary:                actx.Finding.Summary,
		Details:                actx.Finding.Details,
		RepoFullName:           actx.RepoName,
		ManifestPath:           actx.Manifest,
		Ecosystem:              actx.Ecosystem,
		ReachabilityStatus:     actx.ReachabilityStatus,
		ReachabilityConfidence: actx.ReachabilityConfidence,
		ImportSites:            importSites,
		ImportSitesTotal:       total,
		ImportSitesOmitted:     omitted,
		SearchHints:            searchHints,
		IsInternetExposed:      actx.IsInternetExposed,
		AssetCriticality:       actx.AssetCriticality,
		DataSensitivity:        actx.DataSensitivity,
		Environment:            actx.Environment,
	}
}
