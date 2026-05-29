package queue

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/config"
	"go.uber.org/zap"
)

const TaskMaliciousDatasetSyncDaily = "risk:malicious_dataset_sync_daily"

type maliciousDatasetSyncPayload struct{}

type maliciousDatasetSyncHandler struct {
	enabled    bool
	db         *pgxpool.Pool
	log        *zap.Logger
	client     *http.Client
	datasetURL string
}

func NewMaliciousDatasetSyncDailyTask() (*asynq.Task, error) {
	payload, err := json.Marshal(maliciousDatasetSyncPayload{})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TaskMaliciousDatasetSyncDaily, payload, asynq.Queue(QueueDefault)), nil
}

func RegisterMaliciousDatasetHandlers(mux *asynq.ServeMux, db *pgxpool.Pool, cfg *config.Config, log *zap.Logger) {
	h := &maliciousDatasetSyncHandler{
		enabled: cfg.MaliciousDatasetEnabled,
		db:      db,
		log:     log,
		client: &http.Client{
			Timeout: time.Duration(cfg.MaliciousDatasetTimeoutSeconds) * time.Second,
		},
		datasetURL: cfg.MaliciousDatasetURL,
	}
	mux.HandleFunc(TaskMaliciousDatasetSyncDaily, h.Handle)
}

func (h *maliciousDatasetSyncHandler) Handle(ctx context.Context, task *asynq.Task) error {
	var payload maliciousDatasetSyncPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	if !h.enabled {
		return nil
	}

	items, err := h.fetchDataset(ctx)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		return fmt.Errorf("malicious dataset sync returned zero indicators: %s", h.datasetURL)
	}

	tx, err := h.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	upserted := 0
	for _, item := range items {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO malicious_package_indicators (
				source, external_id, ecosystem, package_name, package_version,
				summary, details, published_at, modified_at, withdrawn_at,
				references_json, affected_json, raw_json, last_synced_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10,
				$11::jsonb, $12::jsonb, $13::jsonb, NOW(), NOW()
			)
			ON CONFLICT (source, external_id, ecosystem, package_name, package_version)
			DO UPDATE SET
				summary = EXCLUDED.summary,
				details = EXCLUDED.details,
				published_at = EXCLUDED.published_at,
				modified_at = EXCLUDED.modified_at,
				withdrawn_at = EXCLUDED.withdrawn_at,
				references_json = EXCLUDED.references_json,
				affected_json = EXCLUDED.affected_json,
				raw_json = EXCLUDED.raw_json,
				last_synced_at = NOW(),
				updated_at = NOW()`,
			"openssf",
			item.ExternalID,
			item.Ecosystem,
			item.PackageName,
			item.PackageVersion,
			item.Summary,
			item.Details,
			item.PublishedAt,
			item.ModifiedAt,
			item.WithdrawnAt,
			item.ReferencesJSON,
			item.AffectedJSON,
			item.RawJSON,
		)
		if execErr != nil {
			h.log.Warn("malicious dataset upsert failed",
				zap.String("external_id", item.ExternalID),
				zap.String("ecosystem", item.Ecosystem),
				zap.String("package_name", item.PackageName),
				zap.String("package_version", item.PackageVersion),
				zap.Error(execErr),
			)
			continue
		}
		upserted++
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit malicious dataset sync: %w", err)
	}

	h.log.Info("malicious dataset sync completed",
		zap.String("dataset_url", h.datasetURL),
		zap.Int("loaded", len(items)),
		zap.Int("upserted", upserted),
	)
	return nil
}

type osvRecord struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Published string        `json:"published"`
	Modified  string        `json:"modified"`
	Withdrawn string        `json:"withdrawn"`
	Affected  []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions []string `json:"versions"`
}

type datasetIndicator struct {
	ExternalID     string
	Ecosystem      string
	PackageName    string
	PackageVersion string
	Summary        string
	Details        string
	PublishedAt    *time.Time
	ModifiedAt     *time.Time
	WithdrawnAt    *time.Time
	ReferencesJSON []byte
	AffectedJSON   []byte
	RawJSON        []byte
}

func (h *maliciousDatasetSyncHandler) fetchDataset(ctx context.Context) ([]datasetIndicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.datasetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build dataset request: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/zip")
	req.Header.Set("User-Agent", "devsecops-malicious-sync/1.0")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request dataset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dataset endpoint status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read dataset response: %w", err)
	}

	if isZipPayload(h.datasetURL, resp.Header.Get("Content-Type"), body) {
		return parseOSVZip(body)
	}
	return parseOSVJSON(body)
}

func isZipPayload(url, contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "zip") {
		return true
	}
	if strings.HasSuffix(strings.ToLower(url), ".zip") {
		return true
	}
	return len(body) >= 4 && bytes.Equal(body[0:4], []byte("PK\x03\x04"))
}

func parseOSVZip(body []byte) ([]datasetIndicator, error) {
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open dataset zip: %w", err)
	}

	rawRecords := make([]json.RawMessage, 0, len(reader.File))
	for _, f := range reader.File {
		lowerPath := strings.ToLower(f.Name)
		if !strings.Contains(lowerPath, "/osv/malicious/") || !strings.HasSuffix(lowerPath, ".json") {
			continue
		}

		fileReader, openErr := f.Open()
		if openErr != nil {
			continue
		}
		rawFile, readErr := io.ReadAll(fileReader)
		_ = fileReader.Close()
		if readErr != nil {
			continue
		}
		rawRecords = append(rawRecords, json.RawMessage(rawFile))
	}

	return parseRawOSVRecords(rawRecords), nil
}

func parseOSVJSON(body []byte) ([]datasetIndicator, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}

	switch trimmed[0] {
	case '[':
		var rawRecords []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawRecords); err != nil {
			return nil, fmt.Errorf("decode dataset array: %w", err)
		}
		return parseRawOSVRecords(rawRecords), nil
	case '{':
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &envelope); err != nil {
			return nil, fmt.Errorf("decode dataset object: %w", err)
		}

		if raw, ok := envelope["vulns"]; ok {
			var rawRecords []json.RawMessage
			if err := json.Unmarshal(raw, &rawRecords); err != nil {
				return nil, fmt.Errorf("decode dataset object.vulns: %w", err)
			}
			return parseRawOSVRecords(rawRecords), nil
		}
		if raw, ok := envelope["advisories"]; ok {
			var rawRecords []json.RawMessage
			if err := json.Unmarshal(raw, &rawRecords); err != nil {
				return nil, fmt.Errorf("decode dataset object.advisories: %w", err)
			}
			return parseRawOSVRecords(rawRecords), nil
		}

		return parseRawOSVRecords([]json.RawMessage{trimmed}), nil
	default:
		return nil, fmt.Errorf("unsupported dataset format")
	}
}

func parseRawOSVRecords(rawRecords []json.RawMessage) []datasetIndicator {
	unique := make(map[string]datasetIndicator, len(rawRecords))
	for _, raw := range rawRecords {
		parsed := parseSingleOSVRecord(raw)
		for _, item := range parsed {
			key := strings.ToLower(fmt.Sprintf(
				"%s|%s|%s|%s",
				item.ExternalID,
				item.Ecosystem,
				item.PackageName,
				item.PackageVersion,
			))
			unique[key] = item
		}
	}

	out := make([]datasetIndicator, 0, len(unique))
	for _, item := range unique {
		out = append(out, item)
	}
	return out
}

func parseSingleOSVRecord(raw json.RawMessage) []datasetIndicator {
	var record osvRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(record.ID)), "MAL-") {
		return nil
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil
	}

	refs := envelope["references"]
	if len(bytes.TrimSpace(refs)) == 0 {
		refs = json.RawMessage("[]")
	}
	affectedRaw := envelope["affected"]
	if len(bytes.TrimSpace(affectedRaw)) == 0 {
		affectedRaw = json.RawMessage("[]")
	}

	base := datasetIndicator{
		ExternalID:     strings.TrimSpace(record.ID),
		Summary:        record.Summary,
		Details:        record.Details,
		PublishedAt:    parseRFC3339Ptr(record.Published),
		ModifiedAt:     parseRFC3339Ptr(record.Modified),
		WithdrawnAt:    parseRFC3339Ptr(record.Withdrawn),
		ReferencesJSON: refs,
		AffectedJSON:   affectedRaw,
		RawJSON:        raw,
	}

	items := make([]datasetIndicator, 0)
	for _, affected := range record.Affected {
		ecosystem := strings.TrimSpace(affected.Package.Ecosystem)
		packageName := strings.TrimSpace(affected.Package.Name)
		if ecosystem == "" || packageName == "" {
			continue
		}
		if len(affected.Versions) == 0 {
			item := base
			item.Ecosystem = ecosystem
			item.PackageName = packageName
			item.PackageVersion = ""
			items = append(items, item)
			continue
		}
		for _, version := range affected.Versions {
			item := base
			item.Ecosystem = ecosystem
			item.PackageName = packageName
			item.PackageVersion = strings.TrimSpace(version)
			items = append(items, item)
		}
	}

	return items
}

func parseRFC3339Ptr(raw string) *time.Time {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, clean)
	if err != nil {
		return nil
	}
	utc := parsed.UTC()
	return &utc
}
