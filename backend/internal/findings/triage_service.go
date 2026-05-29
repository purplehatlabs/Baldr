package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/models"
)

const autoConfirmConfidenceThreshold = 0.8

var (
	ErrInvalidTriageTransition = errors.New("invalid triage transition")
	ErrTriageAdminRequired     = errors.New("admin role required to reopen triage")
	ErrFindingNotFound         = errors.New("finding not found")
)

type TriageEvaluationInput struct {
	CriticalityVerdict models.CriticalityVerdict
	ReachabilityStatus models.ReachabilityStatus
	Confidence         float64
}

type TriageEvaluationResult struct {
	Status models.TriageStatus
	Source models.TriageDecisionSource
	Auto   bool
}

func EvaluateTriageFromAnalysis(in TriageEvaluationInput) TriageEvaluationResult {
	if in.CriticalityVerdict == models.VerdictTrueCritical &&
		in.ReachabilityStatus == models.ReachabilityReachable &&
		in.Confidence >= autoConfirmConfidenceThreshold {
		return TriageEvaluationResult{
			Status: models.TriageConfirmed,
			Source: models.TriageDecisionAutoAI,
			Auto:   true,
		}
	}

	return TriageEvaluationResult{Status: models.TriageNeedsReview}
}

func CanManualConfirm(current models.TriageStatus) bool {
	return current == models.TriageNew || current == models.TriageNeedsReview
}

func CanManualDismiss(current models.TriageStatus) bool {
	return current == models.TriageNew || current == models.TriageNeedsReview
}

func CanReopenTriage(current models.TriageStatus, role string) error {
	if current != models.TriageDismissed {
		return fmt.Errorf("%w: only dismissed findings can be reopened", ErrInvalidTriageTransition)
	}
	if role != "admin" && role != "owner" {
		return ErrTriageAdminRequired
	}
	return nil
}

func IsPendingTriage(status models.TriageStatus) bool {
	return status == models.TriageNew || status == models.TriageNeedsReview
}

type TriageService struct {
	db             *pgxpool.Pool
	prioritization *PrioritizationService
}

func NewTriageService(db *pgxpool.Pool) *TriageService {
	return &TriageService{
		db:             db,
		prioritization: NewPrioritizationService(db),
	}
}

type findingTriageRow struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Status       models.FindingStatus
	TriageStatus models.TriageStatus
	Reachability models.ReachabilityStatus
}

func (s *TriageService) ApplyPostAnalysis(
	ctx context.Context,
	findingID, tenantID uuid.UUID,
	criticality models.CriticalityVerdict,
	confidence float64,
) error {
	row, err := s.loadFindingTriageRow(ctx, findingID, tenantID)
	if err != nil {
		return err
	}
	if row.TriageStatus == models.TriageConfirmed || row.TriageStatus == models.TriageDismissed {
		return nil
	}

	result := EvaluateTriageFromAnalysis(TriageEvaluationInput{
		CriticalityVerdict: criticality,
		ReachabilityStatus: row.Reachability,
		Confidence:         confidence,
	})

	return s.applyTriageStatus(ctx, row, result.Status, nil, optionalSource(result.Source))
}

func optionalSource(source models.TriageDecisionSource) *models.TriageDecisionSource {
	if source == "" {
		return nil
	}
	return &source
}

func (s *TriageService) Confirm(ctx context.Context, findingID, tenantID, actorUserID uuid.UUID) error {
	row, err := s.loadFindingTriageRow(ctx, findingID, tenantID)
	if err != nil {
		return err
	}
	if !CanManualConfirm(row.TriageStatus) {
		return ErrInvalidTriageTransition
	}

	source := models.TriageDecisionManual
	return s.applyTriageStatus(ctx, row, models.TriageConfirmed, &actorUserID, &source)
}

func (s *TriageService) Dismiss(ctx context.Context, findingID, tenantID, actorUserID uuid.UUID) error {
	row, err := s.loadFindingTriageRow(ctx, findingID, tenantID)
	if err != nil {
		return err
	}
	if !CanManualDismiss(row.TriageStatus) {
		return ErrInvalidTriageTransition
	}

	source := models.TriageDecisionManual
	return s.applyTriageStatus(ctx, row, models.TriageDismissed, &actorUserID, &source)
}

func (s *TriageService) Reopen(ctx context.Context, findingID, tenantID, actorUserID uuid.UUID, role string) error {
	row, err := s.loadFindingTriageRow(ctx, findingID, tenantID)
	if err != nil {
		return err
	}
	if err := CanReopenTriage(row.TriageStatus, role); err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	now := time.Now().UTC()
	source := models.TriageDecisionManual
	_, err = tx.Exec(ctx, `
		UPDATE findings SET
			triage_status = $1,
			status = $2,
			triage_decided_at = $3,
			triage_decided_by_user_id = $4,
			triage_decision_source = $5
		WHERE id = $6`,
		models.TriageNeedsReview, models.FindingOpen, now, actorUserID, source, findingID,
	)
	if err != nil {
		return err
	}

	if err := insertTriageAuditLog(ctx, tx, tenantID, &actorUserID, findingID, "triage_reopen",
		string(row.TriageStatus), string(models.TriageNeedsReview), map[string]any{"source": "manual"}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	return s.prioritization.RecalculateRiskScore(ctx, findingID, tenantID)
}

func (s *TriageService) loadFindingTriageRow(ctx context.Context, findingID, tenantID uuid.UUID) (findingTriageRow, error) {
	var row findingTriageRow
	err := s.db.QueryRow(ctx, `
		SELECT f.id, COALESCE(f.tenant_id, o.tenant_id), f.status, f.triage_status, f.reachability_status
		FROM findings f
		LEFT JOIN manifests m ON m.id = f.manifest_id
		LEFT JOIN repositories r ON r.id = m.repo_id
		LEFT JOIN organizations o ON o.id = r.org_id
		WHERE f.id = $1 AND (f.tenant_id = $2 OR o.tenant_id = $2)`,
		findingID, tenantID,
	).Scan(&row.ID, &row.TenantID, &row.Status, &row.TriageStatus, &row.Reachability)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return row, ErrFindingNotFound
		}
		return row, err
	}
	return row, nil
}

func (s *TriageService) applyTriageStatus(
	ctx context.Context,
	row findingTriageRow,
	triageStatus models.TriageStatus,
	actorUserID *uuid.UUID,
	source *models.TriageDecisionSource,
) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	now := time.Now().UTC()
	newFindingStatus := row.Status
	if triageStatus == models.TriageDismissed {
		newFindingStatus = models.FindingSuppressed
	}

	_, err = tx.Exec(ctx, `
		UPDATE findings SET
			triage_status = $1,
			status = $2,
			triage_decided_at = $3,
			triage_decided_by_user_id = $4,
			triage_decision_source = $5
		WHERE id = $6`,
		triageStatus, newFindingStatus, now, actorUserID, source, row.ID,
	)
	if err != nil {
		return err
	}

	action := "triage_update"
	switch triageStatus {
	case models.TriageConfirmed:
		action = "triage_confirm"
	case models.TriageDismissed:
		action = "triage_dismiss"
	}

	decisionSource := "manual"
	if source != nil {
		decisionSource = string(*source)
	}
	if err := insertTriageAuditLog(ctx, tx, row.TenantID, actorUserID, row.ID, action,
		string(row.TriageStatus), string(triageStatus), map[string]any{
			"source":                  decisionSource,
			"finding_status":          string(newFindingStatus),
			"previous_finding_status": string(row.Status),
		}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	return s.prioritization.RecalculateRiskScore(ctx, row.ID, row.TenantID)
}

func insertTriageAuditLog(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	actorUserID *uuid.UUID,
	findingID uuid.UUID,
	action string,
	previousStatus string,
	newStatus string,
	metadata map[string]any,
) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO finding_audit_logs
			(tenant_id, finding_id, action, previous_status, new_status, actor_user_id, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		tenantID, findingID, action, previousStatus, newStatus, actorUserID, payload,
	)
	return err
}
