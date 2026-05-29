package findings

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/models"
	"github.com/purplehatlabs/Baldr/internal/scanner"
)

type PrioritizationService struct {
	db *pgxpool.Pool
}

func NewPrioritizationService(db *pgxpool.Pool) *PrioritizationService {
	return &PrioritizationService{db: db}
}

func (s *PrioritizationService) ApplyReachability(
	ctx context.Context,
	findingID uuid.UUID,
	repoRoot string,
	manifest scanner.Manifest,
	packageName string,
) error {
	result := AnalyzeReachability(repoRoot, manifest, packageName)
	evidenceJSON, err := MarshalReachabilityEvidence(result.Evidence)
	if err != nil {
		return err
	}
	now := ReachabilityAnalyzedAtNow()
	_, err = s.db.Exec(ctx, `
		UPDATE findings SET
			reachability_status = $1,
			reachability_confidence = $2,
			reachability_evidence_json = $3,
			reachability_analyzed_at = $4
		WHERE id = $5`,
		result.Status, result.Confidence, evidenceJSON, now, findingID,
	)
	return err
}

func (s *PrioritizationService) RecalculateRiskScore(ctx context.Context, findingID, tenantID uuid.UUID) error {
	var (
		severity           models.Severity
		status             models.FindingStatus
		cvss               *float64
		fixedVersion       *string
		firstSeenAt        time.Time
		reachStatus        models.ReachabilityStatus
		reachConf          *float64
		exploitability     *string
		criticality        *string
		llmConfidence      *float64
		vulnerablePathsRaw []byte
		analysisStatus     *string
		epssScore          *float64
		epssPercentile     *float64
		kevListed          bool
		assetCriticality   string
		dataSensitivity    string
		environment        string
		isInternetExposed  *bool
	)

	err := s.db.QueryRow(ctx, `
		SELECT f.severity, f.status, f.cvss_score, f.fixed_version, f.first_seen_at,
		       f.reachability_status, f.reachability_confidence,
		       fa.exploitability_verdict, fa.criticality_verdict, fa.confidence,
		       fa.vulnerable_code_paths_json, fa.analysis_status,
		       f.epss_score, f.epss_percentile, f.kev_listed,
		       COALESCE(r.asset_criticality, 'medium'),
		       COALESCE(r.data_sensitivity, 'internal'),
		       COALESCE(r.environment, 'prod'),
		       r.is_internet_exposed
		FROM findings f
		LEFT JOIN manifests m ON m.id = f.manifest_id
		LEFT JOIN repositories r ON r.id = m.repo_id
		LEFT JOIN organizations o ON o.id = r.org_id
		LEFT JOIN LATERAL (
			SELECT exploitability_verdict, criticality_verdict, confidence,
			       vulnerable_code_paths_json, analysis_status
			FROM finding_analyses
			WHERE finding_id = f.id AND analysis_status = 'completed'
			ORDER BY created_at DESC
			LIMIT 1
		) fa ON TRUE
		WHERE f.id = $1 AND (f.tenant_id = $2 OR o.tenant_id = $2)`,
		findingID, tenantID,
	).Scan(
		&severity, &status, &cvss, &fixedVersion, &firstSeenAt,
		&reachStatus, &reachConf, &exploitability, &criticality, &llmConfidence,
		&vulnerablePathsRaw, &analysisStatus,
		&epssScore, &epssPercentile, &kevListed,
		&assetCriticality, &dataSensitivity, &environment, &isInternetExposed,
	)
	if err != nil {
		return err
	}

	hasException, err := s.hasActiveException(ctx, tenantID, findingID)
	if err != nil {
		return err
	}

	slaHours, err := s.resolveSLAHours(ctx, tenantID)
	if err != nil {
		return err
	}

	input := RiskScoreInput{
		Severity:                severity,
		CVSSScore:               cvss,
		Status:                  status,
		FixedVersion:            fixedVersion,
		FirstSeenAt:             firstSeenAt,
		ReachabilityStatus:      reachStatus,
		ReachabilityConfidence:  reachConf,
		HasActiveException:      hasException,
		SLAHours:                slaHours,
		EPSSScore:               epssScore,
		EPSSPercentile:          epssPercentile,
		KEVListed:               kevListed,
		AssetCriticality:        assetCriticality,
		DataSensitivity:         dataSensitivity,
		Environment:             environment,
		IsInternetExposed:       isInternetExposed,
		LLMConfidence:           llmConfidence,
		VulnerablePathConfirmed: hasVulnerablePaths(vulnerablePathsRaw),
		HasContextualAnalysis:   analysisStatus != nil && *analysisStatus == string(models.AnalysisCompleted),
	}
	if exploitability != nil {
		v := models.ExploitabilityVerdict(*exploitability)
		input.Exploitability = &v
	}
	if criticality != nil {
		v := models.CriticalityVerdict(*criticality)
		input.CriticalityVerdict = &v
	}

	result := CalculateRiskScore(input, time.Now().UTC())
	factorsJSON, err := MarshalRiskFactors(result.Factors)
	if err != nil {
		return err
	}

	scoredAt := time.Now().UTC()
	_, err = s.db.Exec(ctx, `
		UPDATE findings SET
			risk_score = $1,
			risk_tier = $2,
			risk_factors_json = $3,
			risk_scored_at = $4,
			sla_due_at = $5,
			is_sla_breached = $6
		WHERE id = $7`,
		result.Score, result.Tier, factorsJSON, scoredAt,
		result.SLADueAt, result.IsSLABreach, findingID,
	)
	return err
}

func hasVulnerablePaths(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var paths []string
	if err := json.Unmarshal(raw, &paths); err != nil {
		return false
	}
	return len(paths) > 0
}

func (s *PrioritizationService) hasActiveException(ctx context.Context, tenantID, findingID uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM finding_exceptions
			WHERE tenant_id = $1 AND finding_id = $2
			  AND (expires_at IS NULL OR expires_at > NOW())
		)`, tenantID, findingID,
	).Scan(&exists)
	return exists, err
}

func (s *PrioritizationService) resolveSLAHours(ctx context.Context, tenantID uuid.UUID) (*int, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `
		SELECT pr.value_json
		FROM policy_rules pr
		JOIN policies p ON p.id = pr.policy_id
		WHERE pr.tenant_id = $1
		  AND p.is_enabled = TRUE
		  AND pr.rule_type = 'sla_hours'
		ORDER BY p.updated_at DESC
		LIMIT 1`, tenantID,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nil
	}
	hoursFloat, ok := payload["hours"].(float64)
	if !ok {
		return nil, nil
	}
	hours := int(hoursFloat)
	return &hours, nil
}
