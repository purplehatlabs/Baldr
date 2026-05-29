package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/config"
	findingsvc "github.com/purplehatlabs/Baldr/internal/findings"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

const (
	QueueAnalysis       = "analysis"
	TaskValidateFinding = "validate:finding"
)

type ValidateFindingPayload struct {
	AnalysisID string `json:"analysis_id"`
	FindingID  string `json:"finding_id"`
	TenantID   string `json:"tenant_id"`
}

func NewValidateFindingTask(analysisID, findingID, tenantID uuid.UUID) (*asynq.Task, error) {
	payload, err := json.Marshal(ValidateFindingPayload{
		AnalysisID: analysisID.String(),
		FindingID:  findingID.String(),
		TenantID:   tenantID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TaskValidateFinding, payload, asynq.Queue(QueueAnalysis)), nil
}

type Enqueuer struct {
	client *asynq.Client
}

func NewEnqueuer(client *asynq.Client) *Enqueuer {
	return &Enqueuer{client: client}
}

func (e *Enqueuer) EnqueueFindingAnalysis(analysisID, findingID, tenantID uuid.UUID) error {
	task, err := NewValidateFindingTask(analysisID, findingID, tenantID)
	if err != nil {
		return err
	}
	_, err = e.client.Enqueue(task)
	return err
}

type validateFindingHandler struct {
	svc *findingsvc.Service
	db  *pgxpool.Pool
	log *zap.Logger
}

func RegisterAnalysisHandlers(
	mux *asynq.ServeMux,
	db *pgxpool.Pool,
	ghClient *githubclient.Client,
	cfg *config.Config,
	enqueuer *Enqueuer,
	log *zap.Logger,
) {
	svc := findingsvc.NewService(db, cfg, ghClient, log)
	svc.SetBatchPollEnqueuer(enqueuer.EnqueueBatchTranslationPoll)
	h := &validateFindingHandler{svc: svc, db: db, log: log}
	mux.HandleFunc(TaskValidateFinding, h.Handle)

	batchHandler := &batchTranslationPollHandler{svc: svc, enqueuer: enqueuer, log: log}
	mux.HandleFunc(TaskBatchTranslationPoll, batchHandler.Handle)
}

func (h *validateFindingHandler) Handle(ctx context.Context, t *asynq.Task) error {
	var payload ValidateFindingPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	analysisID, err := uuid.Parse(payload.AnalysisID)
	if err != nil {
		return fmt.Errorf("parse analysis_id: %w", err)
	}
	findingID, err := uuid.Parse(payload.FindingID)
	if err != nil {
		return fmt.Errorf("parse finding_id: %w", err)
	}
	tenantID, err := uuid.Parse(payload.TenantID)
	if err != nil {
		return fmt.Errorf("parse tenant_id: %w", err)
	}
	if err := validateFindingTenant(ctx, h.db, findingID, tenantID); err != nil {
		return err
	}

	log := h.log.With(
		zap.String("analysis_id", payload.AnalysisID),
		zap.String("finding_id", payload.FindingID),
		zap.String("tenant_id", payload.TenantID),
	)
	log.Info("starting finding analysis")

	if err := h.svc.RunAnalysis(ctx, analysisID); err != nil {
		log.Warn("finding analysis failed", zap.Error(err))
		return err
	}
	return nil
}

func EnqueueFindingAnalysisAfterUpsert(
	ctx context.Context,
	enqueuer *Enqueuer,
	svc *findingsvc.Service,
	findingID, tenantID uuid.UUID,
	scanJobID uuid.UUID,
	log *zap.Logger,
) {
	analysisID, created, err := svc.EnqueueAnalysis(ctx, findingID, tenantID, &scanJobID, models.AnalysisTriggerScan, false)
	if err != nil {
		if err.Error() == "analysis already completed for current finding data" {
			return
		}
		log.Warn("prepare finding analysis", zap.String("finding_id", findingID.String()), zap.Error(err))
		return
	}

	if !created {
		return
	}

	if err := enqueuer.EnqueueFindingAnalysis(analysisID, findingID, tenantID); err != nil {
		log.Warn("enqueue finding analysis", zap.String("finding_id", findingID.String()), zap.Error(err))
	}
}
