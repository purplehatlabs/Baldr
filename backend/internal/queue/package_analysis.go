package queue

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/config"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

const TaskPackageDynamicAnalysis = "scan:package_dynamic_analysis"

type PackageDynamicAnalysisPayload struct {
	TenantID        string `json:"tenant_id"`
	Ecosystem       string `json:"ecosystem"`
	PackageName     string `json:"package_name"`
	PackageVersion  string `json:"package_version"`
	TriggerSignalID string `json:"trigger_signal_id,omitempty"`
}

type packageDynamicAnalysisHandler struct {
	db             *pgxpool.Pool
	log            *zap.Logger
	client         *http.Client
	endpointURL    string
	timeoutSeconds int
}

type packageDynamicAnalysisRequest struct {
	TenantID        string `json:"tenant_id"`
	Ecosystem       string `json:"ecosystem"`
	PackageName     string `json:"package_name"`
	PackageVersion  string `json:"package_version"`
	TriggerSignalID string `json:"trigger_signal_id,omitempty"`
}

func NewPackageDynamicAnalysisTask(
	tenantID uuid.UUID,
	ecosystem, packageName, packageVersion string,
	triggerSignalID *uuid.UUID,
) (*asynq.Task, string, error) {
	payload := PackageDynamicAnalysisPayload{
		TenantID:       tenantID.String(),
		Ecosystem:      strings.TrimSpace(ecosystem),
		PackageName:    strings.TrimSpace(packageName),
		PackageVersion: strings.TrimSpace(packageVersion),
	}
	if triggerSignalID != nil {
		payload.TriggerSignalID = triggerSignalID.String()
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal payload: %w", err)
	}

	taskID := packageAnalysisTaskID(payload)
	task := asynq.NewTask(TaskPackageDynamicAnalysis, rawPayload, asynq.Queue(QueueAnalysis))
	return task, taskID, nil
}

func (e *Enqueuer) EnqueuePackageDynamicAnalysis(
	tenantID uuid.UUID,
	ecosystem, packageName, packageVersion string,
	triggerSignalID *uuid.UUID,
) error {
	task, taskID, err := NewPackageDynamicAnalysisTask(tenantID, ecosystem, packageName, packageVersion, triggerSignalID)
	if err != nil {
		return err
	}
	_, err = e.client.Enqueue(task, asynq.TaskID(taskID), asynq.Unique(15*time.Minute))
	return err
}

func (e *Enqueuer) EnqueuePackageDynamicAnalysisFromSignal(
	tenantID uuid.UUID,
	ecosystem, packageName, packageVersion string,
	severity models.Severity,
	triggerSignalID *uuid.UUID,
) error {
	if severity != models.SeverityCritical && severity != models.SeverityHigh {
		return nil
	}
	return e.EnqueuePackageDynamicAnalysis(tenantID, ecosystem, packageName, packageVersion, triggerSignalID)
}

func RegisterPackageDynamicAnalysisHandlers(
	mux *asynq.ServeMux,
	db *pgxpool.Pool,
	cfg *config.Config,
	log *zap.Logger,
) {
	h := &packageDynamicAnalysisHandler{
		db:  db,
		log: log,
		client: &http.Client{
			Timeout: time.Duration(cfg.PackageDynamicAnalysisTimeoutSeconds) * time.Second,
		},
		endpointURL:    strings.TrimSpace(cfg.PackageDynamicAnalysisEndpointURL),
		timeoutSeconds: cfg.PackageDynamicAnalysisTimeoutSeconds,
	}
	mux.HandleFunc(TaskPackageDynamicAnalysis, h.Handle)
}

func (h *packageDynamicAnalysisHandler) Handle(ctx context.Context, t *asynq.Task) error {
	var payload PackageDynamicAnalysisPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	tenantID, err := uuid.Parse(payload.TenantID)
	if err != nil {
		return fmt.Errorf("parse tenant_id: %w", err)
	}

	var triggerSignalID *uuid.UUID
	if payload.TriggerSignalID != "" {
		parsed, parseErr := uuid.Parse(payload.TriggerSignalID)
		if parseErr != nil {
			return fmt.Errorf("parse trigger_signal_id: %w", parseErr)
		}
		triggerSignalID = &parsed
	}

	runID := uuid.New()
	startedAt := time.Now().UTC()
	_, err = h.db.Exec(ctx, `
		INSERT INTO package_dynamic_analysis_runs (
			id, tenant_id, signal_id, package_ecosystem, package_name, package_version,
			engine, status, started_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'package_analysis', 'running', $7, $7, $7)
		ON CONFLICT (tenant_id, signal_id, engine)
		DO UPDATE SET
			status = 'running',
			error_msg = NULL,
			started_at = EXCLUDED.started_at,
			completed_at = NULL,
			updated_at = EXCLUDED.updated_at`,
		runID, tenantID, triggerSignalID, payload.Ecosystem, payload.PackageName, payload.PackageVersion, startedAt,
	)
	if err != nil {
		return fmt.Errorf("create package dynamic analysis run: %w", err)
	}

	if h.endpointURL == "" {
		h.failRun(ctx, runID, "PACKAGE_DYNAMIC_ANALYSIS_ENDPOINT_URL is not configured")
		return fmt.Errorf("%w: package analysis endpoint not configured", asynq.SkipRetry)
	}

	reqPayload, err := json.Marshal(packageDynamicAnalysisRequest(payload))
	if err != nil {
		h.failRun(ctx, runID, "marshal request payload failed")
		return fmt.Errorf("%w: marshal package dynamic analysis request: %v", asynq.SkipRetry, err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(h.timeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.endpointURL, bytes.NewReader(reqPayload))
	if err != nil {
		h.failRun(ctx, runID, "build request failed")
		return fmt.Errorf("%w: build package dynamic analysis request: %v", asynq.SkipRetry, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		h.failRun(ctx, runID, err.Error())
		return fmt.Errorf("%w: package dynamic analysis call failed: %v", asynq.SkipRetry, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		h.failRun(ctx, runID, "read response body failed")
		return fmt.Errorf("%w: read package dynamic analysis response: %v", asynq.SkipRetry, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.failRun(ctx, runID, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncateText(string(body), 400)))
		return fmt.Errorf("%w: package dynamic analysis endpoint returned %d", asynq.SkipRetry, resp.StatusCode)
	}

	evidenceSummary, reportJSON := parsePackageDynamicAnalysisResult(body)
	completedAt := time.Now().UTC()
	_, err = h.db.Exec(ctx, `
		UPDATE package_dynamic_analysis_runs
		SET status = 'completed',
		    summary = $1,
		    report_json = $2::jsonb,
		    completed_at = $3,
		    updated_at = $3
		WHERE id = $4`,
		evidenceSummary, reportJSON, completedAt, runID,
	)
	if err != nil {
		return fmt.Errorf("update package dynamic analysis run: %w", err)
	}

	h.log.Info("package dynamic analysis completed",
		zap.String("tenant_id", payload.TenantID),
		zap.String("ecosystem", payload.Ecosystem),
		zap.String("package_name", payload.PackageName),
		zap.String("package_version", payload.PackageVersion),
	)
	return nil
}

func (h *packageDynamicAnalysisHandler) failRun(ctx context.Context, runID uuid.UUID, errMsg string) {
	completedAt := time.Now().UTC()
	_, _ = h.db.Exec(ctx, `
		UPDATE package_dynamic_analysis_runs
		SET status = 'failed',
		    error_msg = $1,
		    completed_at = $2,
		    updated_at = $2
		WHERE id = $3`,
		errMsg, completedAt, runID,
	)
}

func parsePackageDynamicAnalysisResult(raw []byte) (string, []byte) {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		fallback := map[string]any{
			"raw_body": truncateText(string(raw), 4000),
		}
		reportJSON, _ := json.Marshal(fallback)
		return truncateText(string(raw), 2000), reportJSON
	}

	report := map[string]any{
		"raw_response": decoded,
	}
	if object, ok := decoded.(map[string]any); ok {
		if iocs, exists := object["iocs"]; exists {
			report["iocs"] = iocs
		}
	}

	evidenceSummary := extractEvidenceSummary(decoded)
	if evidenceSummary != "" {
		report["evidence_summary"] = evidenceSummary
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return evidenceSummary, []byte(`{}`)
	}
	if evidenceSummary == "" {
		evidenceSummary = truncateText(string(raw), 2000)
	}
	return evidenceSummary, reportJSON
}

func extractEvidenceSummary(decoded any) string {
	object, ok := decoded.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"evidence_summary", "summary", "evidence"} {
		value, exists := object[key]
		if !exists {
			continue
		}
		asString := strings.TrimSpace(fmt.Sprintf("%v", value))
		if asString != "" && asString != "<nil>" {
			return truncateText(asString, 2000)
		}
	}
	return ""
}

func packageAnalysisTaskID(payload PackageDynamicAnalysisPayload) string {
	hashInput := strings.ToLower(strings.TrimSpace(payload.TenantID)) + "|" +
		strings.ToLower(strings.TrimSpace(payload.Ecosystem)) + "|" +
		strings.ToLower(strings.TrimSpace(payload.PackageName)) + "|" +
		strings.TrimSpace(payload.PackageVersion) + "|" +
		strings.ToLower(strings.TrimSpace(payload.TriggerSignalID))
	sum := sha1.Sum([]byte(hashInput))
	return "package-analysis:" + hex.EncodeToString(sum[:])
}

func truncateText(raw string, max int) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max]
}
