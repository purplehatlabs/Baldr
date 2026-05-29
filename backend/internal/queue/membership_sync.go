package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/membership"
	"go.uber.org/zap"
)

const TaskMembershipSync = "github:membership_sync"

type MembershipSyncPayload struct {
	OrgID    string `json:"org_id"`
	TenantID string `json:"tenant_id"`
}

func NewMembershipSyncTask(orgID, tenantID uuid.UUID) (*asynq.Task, error) {
	payload, err := json.Marshal(MembershipSyncPayload{
		OrgID:    orgID.String(),
		TenantID: tenantID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TaskMembershipSync, payload, asynq.Queue(QueueDefault)), nil
}

func (e *Enqueuer) EnqueueMembershipSync(orgID, tenantID uuid.UUID) error {
	task, err := NewMembershipSyncTask(orgID, tenantID)
	if err != nil {
		return err
	}
	taskID := fmt.Sprintf("membership-sync:%s", orgID.String())
	_, err = e.client.Enqueue(task, asynq.TaskID(taskID), asynq.Unique(30*time.Minute))
	return err
}

type membershipSyncHandler struct {
	svc *membership.Service
	log *zap.Logger
}

func RegisterMembershipSyncHandlers(
	mux *asynq.ServeMux,
	db *pgxpool.Pool,
	ghClient *githubclient.Client,
	log *zap.Logger,
) {
	h := &membershipSyncHandler{
		svc: membership.NewService(db, ghClient, log),
		log: log,
	}
	mux.HandleFunc(TaskMembershipSync, h.Handle)
}

func (h *membershipSyncHandler) Handle(ctx context.Context, t *asynq.Task) error {
	var payload MembershipSyncPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	orgID, err := uuid.Parse(payload.OrgID)
	if err != nil {
		return fmt.Errorf("parse org_id: %w", err)
	}
	tenantID, err := uuid.Parse(payload.TenantID)
	if err != nil {
		return fmt.Errorf("parse tenant_id: %w", err)
	}

	_, err = h.svc.SyncOrg(ctx, tenantID, orgID)
	return err
}
