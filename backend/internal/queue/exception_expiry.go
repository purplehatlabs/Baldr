package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	findingsvc "github.com/purplehatlabs/Baldr/internal/findings"
	"go.uber.org/zap"
)

const TaskExpireExceptions = "governance:expire_exceptions"

type ExpireExceptionsPayload struct {
	RunDate string `json:"run_date"`
}

func NewExpireExceptionsTask(runDate time.Time) (*asynq.Task, error) {
	payload, err := json.Marshal(ExpireExceptionsPayload{
		RunDate: runDate.Format(time.DateOnly),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TaskExpireExceptions, payload, asynq.Queue(QueueDefault)), nil
}

type expireExceptionsHandler struct {
	db             *pgxpool.Pool
	log            *zap.Logger
	prioritization *findingsvc.PrioritizationService
}

func RegisterExceptionExpiryHandlers(mux *asynq.ServeMux, db *pgxpool.Pool, log *zap.Logger) {
	h := &expireExceptionsHandler{
		db:             db,
		log:            log,
		prioritization: findingsvc.NewPrioritizationService(db),
	}
	mux.HandleFunc(TaskExpireExceptions, h.Handle)
}

type expiredException struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	FindingID uuid.UUID
}

func (h *expireExceptionsHandler) Handle(ctx context.Context, _ *asynq.Task) error {
	rows, err := h.db.Query(ctx, `
		DELETE FROM finding_exceptions
		WHERE expires_at IS NOT NULL AND expires_at <= NOW()
		RETURNING id, tenant_id, finding_id`)
	if err != nil {
		return fmt.Errorf("expire exceptions: %w", err)
	}
	defer rows.Close()

	expired := make([]expiredException, 0)
	for rows.Next() {
		var item expiredException
		if err := rows.Scan(&item.ID, &item.TenantID, &item.FindingID); err != nil {
			continue
		}
		expired = append(expired, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("scan expired exceptions: %w", err)
	}

	for _, item := range expired {
		if err := h.writeExpiryAuditLog(ctx, item); err != nil {
			h.log.Warn("exception expiry audit log", zap.Error(err), zap.String("finding_id", item.FindingID.String()))
		}
		if err := h.prioritization.RecalculateRiskScore(ctx, item.FindingID, item.TenantID); err != nil {
			h.log.Warn("recalculate risk score after exception expiry", zap.Error(err), zap.String("finding_id", item.FindingID.String()))
		}
	}

	h.log.Info("expired finding exceptions", zap.Int("deleted", len(expired)))
	return nil
}

func (h *expireExceptionsHandler) writeExpiryAuditLog(ctx context.Context, item expiredException) error {
	metadata, err := json.Marshal(map[string]any{
		"exception_id": item.ID.String(),
		"source":       "governance_job",
	})
	if err != nil {
		return err
	}

	_, err = h.db.Exec(ctx, `
		INSERT INTO finding_audit_logs
			(tenant_id, finding_id, action, previous_status, new_status, actor_user_id, metadata, created_at)
		VALUES ($1, $2, 'exception_expired', NULL, NULL, NULL, $3, NOW())`,
		item.TenantID, item.FindingID, metadata,
	)
	return err
}
