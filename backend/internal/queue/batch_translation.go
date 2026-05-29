package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	findingsvc "github.com/purplehatlabs/Baldr/internal/findings"
	"go.uber.org/zap"
)

const TaskBatchTranslationPoll = "analysis:batch_translation_poll"

type BatchTranslationPollPayload struct {
	AnalysisID string `json:"analysis_id"`
}

func NewBatchTranslationPollTask(analysisID uuid.UUID) (*asynq.Task, error) {
	payload, err := json.Marshal(BatchTranslationPollPayload{
		AnalysisID: analysisID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(
		TaskBatchTranslationPoll,
		payload,
		asynq.Queue(QueueAnalysis),
		asynq.ProcessIn(30*time.Second),
	), nil
}

func (e *Enqueuer) EnqueueBatchTranslationPoll(analysisID uuid.UUID) error {
	task, err := NewBatchTranslationPollTask(analysisID)
	if err != nil {
		return err
	}
	_, err = e.client.Enqueue(task)
	return err
}

type batchTranslationPollHandler struct {
	svc      *findingsvc.Service
	enqueuer *Enqueuer
	log      *zap.Logger
}

func (h *batchTranslationPollHandler) Handle(ctx context.Context, t *asynq.Task) error {
	var payload BatchTranslationPollPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	analysisID, err := uuid.Parse(payload.AnalysisID)
	if err != nil {
		return fmt.Errorf("parse analysis_id: %w", err)
	}

	if err := h.svc.PollBatchTranslation(ctx, analysisID); err != nil {
		if errors.Is(err, findingsvc.ErrBatchStillPending) {
			return h.enqueuer.EnqueueBatchTranslationPoll(analysisID)
		}
		h.log.Warn("batch translation poll failed",
			zap.String("analysis_id", payload.AnalysisID),
			zap.Error(err),
		)
		return err
	}
	return nil
}
