package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/config"
	"github.com/purplehatlabs/Baldr/internal/findings/codeagent"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/llm"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type Service struct {
	db       *pgxpool.Pool
	resolver *llm.Resolver
	github   *githubclient.Client
	log      *zap.Logger
}

// NewService builds the analysis Service. The LLM client is no longer process-wide:
// each analysis resolves per-tenant settings (from tenant_llm_configs, with env
// fallback) and constructs a Client tailored to that tenant.
func NewService(db *pgxpool.Pool, cfg *config.Config, gh *githubclient.Client, log *zap.Logger) *Service {
	fallback := llm.Settings{
		BaseURL:                 cfg.LiteLLMBaseURL,
		APIKey:                  cfg.LiteLLMAPIKey,
		Model:                   cfg.LiteLLMModel,
		TimeoutSeconds:          cfg.LiteLLMTimeoutSeconds,
		AutoAnalysisMinSeverity: llm.DefaultAutoAnalysisMinSeverity,
	}
	return &Service{
		db:       db,
		resolver: llm.NewResolver(db, cfg.PEMEncryptionKey, fallback),
		github:   gh,
		log:      log,
	}
}

type FindingContextRow struct {
	Finding   models.Finding
	TenantID  uuid.UUID
	RepoName  string
	Manifest  string
	Ecosystem string
}

func (s *Service) ShouldAutoAnalyze(ctx context.Context, tenantID uuid.UUID, severity models.Severity) (bool, models.Severity, error) {
	minSeverity, err := s.resolver.ResolveAutoAnalysisMinSeverity(ctx, tenantID)
	if err != nil {
		return false, "", err
	}
	return llm.MeetsMinSeverity(severity, minSeverity), minSeverity, nil
}

func (s *Service) AutoAnalysisSkipReason(severity, minSeverity models.Severity) string {
	return fmt.Sprintf(
		"severity %s below tenant auto-analysis threshold (%s)",
		severity,
		minSeverity,
	)
}

func (s *Service) InputHash(row FindingContextRow) string {
	fixed := ""
	if row.Finding.FixedVersion != nil {
		fixed = *row.Finding.FixedVersion
	}
	cvss := ""
	if row.Finding.CVSSScore != nil {
		cvss = fmt.Sprintf("%.1f", *row.Finding.CVSSScore)
	}
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		row.Finding.OSVID, row.Finding.PackageName, row.Finding.PackageVersion,
		row.Finding.Severity, row.Finding.Summary, fixed, cvss, row.Manifest,
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Service) LoadFindingContext(ctx context.Context, findingID, tenantID uuid.UUID) (*FindingContextRow, error) {
	var row FindingContextRow
	var fixedVersion *string
	var cvssScore *float64
	err := s.db.QueryRow(ctx, `
		SELECT f.id, f.scan_job_id, f.manifest_id, f.osv_id, f.package_name,
		       f.package_version, f.fixed_version, f.severity, f.cvss_score,
		       f.summary, f.details, f.status, f.first_seen_at, f.last_seen_at,
		       o.tenant_id, r.full_name, m.path, m.ecosystem
		FROM findings f
		JOIN manifests m ON m.id = f.manifest_id
		JOIN repositories r ON r.id = m.repo_id
		JOIN organizations o ON o.id = r.org_id
		WHERE f.id = $1 AND o.tenant_id = $2`,
		findingID, tenantID,
	).Scan(
		&row.Finding.ID, &row.Finding.ScanJobID, &row.Finding.ManifestID,
		&row.Finding.OSVID, &row.Finding.PackageName, &row.Finding.PackageVersion,
		&fixedVersion, &row.Finding.Severity, &cvssScore,
		&row.Finding.Summary, &row.Finding.Details, &row.Finding.Status,
		&row.Finding.FirstSeenAt, &row.Finding.LastSeenAt,
		&row.TenantID, &row.RepoName, &row.Manifest, &row.Ecosystem,
	)
	if err != nil {
		return nil, fmt.Errorf("load finding: %w", err)
	}
	row.Finding.FixedVersion = fixedVersion
	row.Finding.CVSSScore = cvssScore
	return &row, nil
}

func (s *Service) HasCompletedAnalysis(ctx context.Context, findingID uuid.UUID, inputHash string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM finding_analyses
			WHERE finding_id = $1 AND input_hash = $2 AND analysis_status = 'completed'
		)`, findingID, inputHash,
	).Scan(&exists)
	return exists, err
}

func (s *Service) CreatePendingAnalysis(
	ctx context.Context,
	findingID, tenantID uuid.UUID,
	scanJobID *uuid.UUID,
	trigger models.AnalysisTrigger,
	inputHash string,
) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.db.Exec(ctx, `
		INSERT INTO finding_analyses
			(id, tenant_id, finding_id, scan_job_id, analysis_status, trigger_source, input_hash, created_at)
		VALUES ($1, $2, $3, $4, 'pending', $5, $6, NOW())`,
		id, tenantID, findingID, scanJobID, trigger, inputHash,
	)
	return id, err
}

func (s *Service) RunAnalysis(ctx context.Context, analysisID uuid.UUID) error {
	var findingID, tenantID uuid.UUID
	var trigger models.AnalysisTrigger
	var inputHash *string
	err := s.db.QueryRow(ctx, `
		SELECT finding_id, tenant_id, trigger_source, input_hash
		FROM finding_analyses WHERE id = $1`, analysisID,
	).Scan(&findingID, &tenantID, &trigger, &inputHash)
	if err != nil {
		return fmt.Errorf("load analysis: %w", err)
	}

	now := time.Now()
	_, err = s.db.Exec(ctx, `
		UPDATE finding_analyses SET analysis_status = 'running', started_at = $1 WHERE id = $2`,
		now, analysisID,
	)
	if err != nil {
		return fmt.Errorf("mark running: %w", err)
	}

	row, err := s.LoadFindingContext(ctx, findingID, tenantID)
	if err != nil {
		return s.failAnalysis(ctx, analysisID, err)
	}

	actx, err := s.LoadAnalysisContext(ctx, findingID, tenantID)
	if err != nil {
		return s.failAnalysis(ctx, analysisID, err)
	}

	hash := s.InputHash(*row)
	if inputHash != nil && *inputHash != "" && *inputHash != hash {
		hash = *inputHash
	}

	var minSeverity *models.Severity
	if trigger != models.AnalysisTriggerManual {
		ms, err := s.resolver.ResolveAutoAnalysisMinSeverity(ctx, tenantID)
		if err != nil {
			return s.failAnalysis(ctx, analysisID, fmt.Errorf("resolve auto-analysis threshold: %w", err))
		}
		minSeverity = &ms
	}
	pre := ApplyPreRules(row.Finding.Status, row.Finding.Severity, row.Finding.CVSSScore, minSeverity)
	if pre.SkipAnalysis {
		if strings.Contains(pre.Reason, "below tenant auto-analysis threshold") {
			s.log.Info("finding analysis skipped due to severity policy",
				zap.String("analysis_id", analysisID.String()),
				zap.String("finding_id", findingID.String()),
				zap.String("tenant_id", tenantID.String()),
				zap.String("severity", string(row.Finding.Severity)),
				zap.String("reason", pre.Reason),
			)
		}
		return s.completeSkipped(ctx, analysisID, pre.Reason, hash)
	}

	settings, err := s.resolver.Resolve(ctx, tenantID)
	if err != nil {
		return s.failAnalysis(ctx, analysisID, fmt.Errorf("resolve llm settings: %w", err))
	}

	cloneDir, cleanup, err := s.resolveRepoClone(ctx, actx)
	if err != nil {
		return s.failAnalysis(ctx, analysisID, fmt.Errorf("resolve repo clone: %w", err))
	}
	defer cleanup()

	agentClient := llm.NewAgentClient(settings)
	runner := codeagent.NewAgentRunner(agentClient)
	agentStarted := time.Now()
	agentResult, err := runner.Run(ctx, cloneDir, buildCodeAgentBootstrap(actx))
	if err != nil {
		return s.failAnalysis(ctx, analysisID, err)
	}

	llmResult := &agentResult.Analysis.AnalysisResult
	final := MergeWithLLM(pre, llmResult, row.Finding.Severity)
	modelName := agentClient.ModelName()
	promptVersion := llm.AgentPromptVersion
	completedAt := time.Now()

	var reasoningPtBR, exploitationPtBR, remediationPtBR *string
	translationClient := llm.New(settings)
	translation, translateErr := translationClient.TranslateAnalysisToPtBR(ctx, llm.AnalysisTranslationInput{
		Reasoning:        final.Reasoning,
		ExploitationPath: llmResult.ExploitationPath,
		RemediationPath:  llmResult.RemediationPath,
	})
	if translateErr != nil {
		s.log.Warn("translate analysis to pt-BR",
			zap.String("analysis_id", analysisID.String()),
			zap.String("finding_id", findingID.String()),
			zap.Error(translateErr),
		)
	} else if translation != nil {
		if translation.Reasoning != "" {
			reasoningPtBR = &translation.Reasoning
		}
		if translation.ExploitationPath != "" {
			exploitationPtBR = &translation.ExploitationPath
		}
		if translation.RemediationPath != "" {
			remediationPtBR = &translation.RemediationPath
		}
	}

	_, err = s.db.Exec(ctx, `
		UPDATE finding_analyses SET
			analysis_status = 'completed',
			criticality_verdict = $1,
			exploitability_verdict = $2,
			confidence = $3,
			reasoning = $4,
			exploitation_path = $5,
			remediation_path = $6,
			reasoning_pt_br = $7,
			exploitation_path_pt_br = $8,
			remediation_path_pt_br = $9,
			model_name = $10,
			prompt_version = $11,
			input_hash = $12,
			agent_trace_json = $13,
			vulnerable_code_paths_json = $14,
			completed_at = $15,
			error_msg = NULL
		WHERE id = $16`,
		final.CriticalityVerdict, final.ExploitabilityVerdict, final.Confidence,
		final.Reasoning, llmResult.ExploitationPath, llmResult.RemediationPath,
		reasoningPtBR, exploitationPtBR, remediationPtBR,
		modelName, promptVersion, hash, agentResult.AgentTraceJSON, agentResult.VulnPathsJSON,
		completedAt, analysisID,
	)
	if err != nil {
		return fmt.Errorf("save analysis: %w", err)
	}

	s.log.Info("finding agent analysis completed",
		zap.String("analysis_id", analysisID.String()),
		zap.String("finding_id", findingID.String()),
		zap.String("trigger", string(trigger)),
		zap.Int("agent_turns", agentResult.Trace.Turns),
		zap.Int("agent_tool_calls", agentResult.Trace.ToolCalls),
		zap.Int64("agent_duration_ms", agentResult.Trace.Duration),
		zap.Int64("total_duration_ms", time.Since(agentStarted).Milliseconds()),
		zap.Float64("confidence", final.Confidence),
		zap.String("criticality_verdict", string(final.CriticalityVerdict)),
		zap.String("exploitability_verdict", string(final.ExploitabilityVerdict)),
	)

	prioritization := NewPrioritizationService(s.db)
	if err := prioritization.RecalculateRiskScore(ctx, findingID, tenantID); err != nil {
		s.log.Warn("recalculate risk score after analysis", zap.Error(err))
	}

	triage := NewTriageService(s.db)
	if err := triage.ApplyPostAnalysis(ctx, findingID, tenantID, final.CriticalityVerdict, final.Confidence); err != nil {
		s.log.Warn("apply triage after analysis", zap.Error(err))
	}
	return nil
}

func (s *Service) completeSkipped(ctx context.Context, analysisID uuid.UUID, reason, inputHash string) error {
	completedAt := time.Now()
	_, err := s.db.Exec(ctx, `
		UPDATE finding_analyses SET
			analysis_status = 'skipped',
			reasoning = $1,
			input_hash = $2,
			completed_at = $3
		WHERE id = $4`,
		reason, inputHash, completedAt, analysisID,
	)
	return err
}

func (s *Service) failAnalysis(ctx context.Context, analysisID uuid.UUID, cause error) error {
	errMsg := cause.Error()
	completedAt := time.Now()
	_, _ = s.db.Exec(ctx, `
		UPDATE finding_analyses SET
			analysis_status = 'failed',
			error_msg = $1,
			completed_at = $2
		WHERE id = $3`,
		errMsg, completedAt, analysisID,
	)
	return cause
}

func (s *Service) EnqueueAnalysis(
	ctx context.Context,
	findingID, tenantID uuid.UUID,
	scanJobID *uuid.UUID,
	trigger models.AnalysisTrigger,
	force bool,
) (uuid.UUID, bool, error) {
	row, err := s.LoadFindingContext(ctx, findingID, tenantID)
	if err != nil {
		return uuid.Nil, false, err
	}

	hash := s.InputHash(*row)
	if !force {
		done, err := s.HasCompletedAnalysis(ctx, findingID, hash)
		if err != nil {
			return uuid.Nil, false, err
		}
		if done {
			return uuid.Nil, false, fmt.Errorf("analysis already completed for current finding data")
		}
	}

	if trigger == models.AnalysisTriggerScan {
		ok, minSeverity, err := s.ShouldAutoAnalyze(ctx, tenantID, row.Finding.Severity)
		if err != nil {
			return uuid.Nil, false, err
		}
		if !ok {
			s.log.Info("skipping LLM auto-analysis due to severity policy",
				zap.String("finding_id", findingID.String()),
				zap.String("tenant_id", tenantID.String()),
				zap.String("severity", string(row.Finding.Severity)),
				zap.String("min_severity", string(minSeverity)),
			)
			return uuid.Nil, false, nil
		}
	}

	var pendingID uuid.UUID
	err = s.db.QueryRow(ctx, `
		SELECT id FROM finding_analyses
		WHERE finding_id = $1 AND analysis_status IN ('pending', 'running')
		ORDER BY created_at DESC LIMIT 1`, findingID,
	).Scan(&pendingID)
	if err == nil {
		return pendingID, false, nil
	}

	id, err := s.CreatePendingAnalysis(ctx, findingID, tenantID, scanJobID, trigger, hash)
	return id, true, err
}
