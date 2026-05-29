package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const (
	TaskThreatIntelDaily = "risk:threat_intel_daily"
	epssAPIURL           = "https://api.first.org/data/v1/epss?cve=%s"
	kevFeedURL           = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

type threatIntelDailyPayload struct{}

type threatIntelDailyHandler struct {
	db     *pgxpool.Pool
	log    *zap.Logger
	client *http.Client
}

func NewThreatIntelDailyTask() (*asynq.Task, error) {
	payload, err := json.Marshal(threatIntelDailyPayload{})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TaskThreatIntelDaily, payload, asynq.Queue(QueueDefault)), nil
}

func RegisterThreatIntelHandlers(mux *asynq.ServeMux, db *pgxpool.Pool, log *zap.Logger) {
	h := &threatIntelDailyHandler{
		db:  db,
		log: log,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
	mux.HandleFunc(TaskThreatIntelDaily, h.Handle)
}

func (h *threatIntelDailyHandler) Handle(ctx context.Context, t *asynq.Task) error {
	var payload threatIntelDailyPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	type findingThreatRow struct {
		ID    uuid.UUID
		OSVID string
	}

	rows, err := h.db.Query(ctx, `
		SELECT id, osv_id
		FROM findings
		WHERE status = 'open'
		  AND (threat_updated_at IS NULL OR threat_updated_at < NOW() - INTERVAL '1 day')
		ORDER BY last_seen_at DESC
		LIMIT 500`)
	if err != nil {
		return fmt.Errorf("load findings for threat enrichment: %w", err)
	}
	defer rows.Close()

	targets := make([]findingThreatRow, 0, 500)
	cveSet := make(map[string]struct{})
	for rows.Next() {
		var row findingThreatRow
		if err := rows.Scan(&row.ID, &row.OSVID); err != nil {
			continue
		}
		targets = append(targets, row)
		if cve := normalizeCVE(row.OSVID); cve != "" {
			cveSet[cve] = struct{}{}
		}
	}
	if len(targets) == 0 {
		return nil
	}

	kevSet, kevErr := h.fetchKEVSet(ctx)
	if kevErr != nil {
		h.log.Warn("threat-intel: could not fetch KEV feed", zap.Error(kevErr))
		kevSet = map[string]struct{}{}
	}

	epssByCVE := map[string]epssRecord{}
	cves := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cves = append(cves, cve)
	}
	if len(cves) > 0 {
		m, epssErr := h.fetchEPSSBatch(ctx, cves)
		if epssErr != nil {
			h.log.Warn("threat-intel: could not fetch EPSS scores", zap.Error(epssErr))
		} else {
			epssByCVE = m
		}
	}

	updated := 0
	for _, row := range targets {
		cve := normalizeCVE(row.OSVID)

		var epssScore *float64
		var epssPercentile *float64
		if rec, ok := epssByCVE[cve]; ok {
			epssScore = rec.Score
			epssPercentile = rec.Percentile
		}

		_, err := h.db.Exec(ctx, `
			UPDATE findings
			SET epss_score = $1,
			    epss_percentile = $2,
			    kev_listed = $3,
			    threat_updated_at = NOW()
			WHERE id = $4`,
			epssScore,
			epssPercentile,
			isInSet(kevSet, cve),
			row.ID,
		)
		if err != nil {
			h.log.Warn("threat-intel: update failed", zap.String("finding_id", row.ID.String()), zap.Error(err))
			continue
		}
		updated++
	}

	h.log.Info("threat-intel: enrichment completed",
		zap.Int("targets", len(targets)),
		zap.Int("updated", updated),
	)
	return nil
}

type kevFeedResponse struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func (h *threatIntelDailyHandler) fetchKEVSet(ctx context.Context) (map[string]struct{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevFeedURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("KEV feed status %d", resp.StatusCode)
	}

	var payload kevFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(payload.Vulnerabilities))
	for _, item := range payload.Vulnerabilities {
		if cve := normalizeCVE(item.CVEID); cve != "" {
			out[cve] = struct{}{}
		}
	}
	return out, nil
}

type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

type epssRecord struct {
	Score      *float64
	Percentile *float64
}

func (h *threatIntelDailyHandler) fetchEPSSBatch(ctx context.Context, cves []string) (map[string]epssRecord, error) {
	out := make(map[string]epssRecord, len(cves))
	for i := 0; i < len(cves); i += 100 {
		end := i + 100
		if end > len(cves) {
			end = len(cves)
		}
		chunk := strings.Join(cves[i:end], ",")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(epssAPIURL, chunk), nil)
		if err != nil {
			return nil, err
		}
		resp, err := h.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("EPSS API status %d", resp.StatusCode)
		}
		var payload epssResponse
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		_ = resp.Body.Close()

		for _, item := range payload.Data {
			normalized := normalizeCVE(item.CVE)
			if normalized == "" {
				continue
			}
			out[normalized] = epssRecord{
				Score:      parseFloatPointer(item.EPSS),
				Percentile: parseFloatPointer(item.Percentile),
			}
		}
	}
	return out, nil
}

func normalizeCVE(raw string) string {
	v := strings.TrimSpace(strings.ToUpper(raw))
	if strings.HasPrefix(v, "CVE-") {
		return v
	}
	return ""
}

func parseFloatPointer(raw string) *float64 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}
	return &parsed
}

func isInSet(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}
