package findings

import (
	"encoding/json"
	"errors"

	"github.com/purplehatlabs/Baldr/internal/llm"
	"github.com/purplehatlabs/Baldr/internal/models"
)

var ErrBatchStillPending = errors.New("batch translation still pending")

type dispatchMeta struct {
	Reason  string `json:"reason,omitempty"`
	Phase   string `json:"phase,omitempty"`
	BatchID string `json:"batch_id,omitempty"`
}

func shouldBatchTranslate(settings llm.Settings, trigger models.AnalysisTrigger) bool {
	return settings.BatchEnabled && trigger == models.AnalysisTriggerScan
}

func agentDispatchMeta(settings llm.Settings) ([]byte, models.LLMDispatchMode) {
	if !settings.BatchEnabled {
		return nil, models.LLMDispatchRealtime
	}
	meta, _ := json.Marshal(dispatchMeta{
		Phase:  "agentic",
		Reason: "agentic_multi_turn_tools_not_batchable",
	})
	return meta, models.LLMDispatchBatchFallback
}

func batchPendingMeta(batchID string) []byte {
	meta, _ := json.Marshal(dispatchMeta{
		Phase:   "translation",
		BatchID: batchID,
	})
	return meta
}

func batchDoneMeta(batchID string) []byte {
	meta, _ := json.Marshal(dispatchMeta{
		Phase:   "translation",
		BatchID: batchID,
		Reason:  "batch_completed",
	})
	return meta
}

func batchFallbackMeta(batchID, reason string) []byte {
	meta, _ := json.Marshal(dispatchMeta{
		Phase:   "translation",
		BatchID: batchID,
		Reason:  reason,
	})
	return meta
}
