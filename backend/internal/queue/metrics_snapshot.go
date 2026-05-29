package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const TaskMetricsSnapshotDaily = "metrics:snapshot_daily"

type MetricsSnapshotPayload struct {
	SnapshotDate string `json:"snapshot_date,omitempty"`
}

func NewMetricsSnapshotDailyTask(snapshotDate time.Time) (*asynq.Task, error) {
	payload := MetricsSnapshotPayload{}
	if !snapshotDate.IsZero() {
		payload.SnapshotDate = snapshotDate.UTC().Format(time.DateOnly)
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	return asynq.NewTask(TaskMetricsSnapshotDaily, rawPayload, asynq.Queue(QueueDefault)), nil
}

type metricsSnapshotHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func RegisterMetricsSnapshotHandlers(mux *asynq.ServeMux, db *pgxpool.Pool, log *zap.Logger) {
	h := &metricsSnapshotHandler{
		db:  db,
		log: log,
	}
	mux.HandleFunc(TaskMetricsSnapshotDaily, h.HandleDailySnapshot)
}

func (h *metricsSnapshotHandler) HandleDailySnapshot(ctx context.Context, task *asynq.Task) error {
	var payload MetricsSnapshotPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	snapshotDate, err := parseSnapshotDate(payload.SnapshotDate)
	if err != nil {
		return err
	}

	tenantCount, err := h.upsertDailySnapshot(ctx, snapshotDate)
	if err != nil {
		return err
	}

	h.log.Info("daily metrics snapshot completed",
		zap.String("snapshot_date", snapshotDate.Format(time.DateOnly)),
		zap.Int64("tenant_count", tenantCount),
	)
	return nil
}

func parseSnapshotDate(raw string) (time.Time, error) {
	if raw == "" {
		now := time.Now().UTC()
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1), nil
	}

	snapshotDate, err := time.Parse(time.DateOnly, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse snapshot_date: %w", err)
	}
	return snapshotDate.UTC(), nil
}

func (h *metricsSnapshotHandler) upsertDailySnapshot(ctx context.Context, snapshotDate time.Time) (int64, error) {
	tag, err := h.db.Exec(ctx, `
		WITH tenant_repos AS (
			SELECT
				o.tenant_id,
				COUNT(*) FILTER (WHERE r.is_archived = FALSE) AS total_repos,
				COUNT(*) FILTER (WHERE r.is_archived = FALSE AND r.last_scanned_at >= NOW() - INTERVAL '30 days') AS scanned_repos_30d
			FROM organizations o
			LEFT JOIN repositories r ON r.org_id = o.id
			GROUP BY o.tenant_id
		),
		tenant_findings AS (
			SELECT
				o.tenant_id,
				COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'critical') AS open_critical,
				COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'high') AS open_high,
				COUNT(*) FILTER (WHERE f.status = 'open') AS open_total,
				COUNT(*) FILTER (
					WHERE f.status = 'open'
					AND (
						(f.severity = 'critical' AND f.first_seen_at <= NOW() - INTERVAL '7 days')
						OR
						(f.severity = 'high' AND f.first_seen_at <= NOW() - INTERVAL '30 days')
					)
				) AS open_high_plus_sla_breach,
				AVG(CASE
					WHEN f.status = 'fixed' AND f.severity IN ('critical', 'high')
					THEN EXTRACT(EPOCH FROM (f.last_seen_at - f.first_seen_at)) / 3600
				END) AS mttr_high_plus_hours,
				COUNT(*) FILTER (
					WHERE f.status = 'open'
					AND f.severity = 'critical'
					AND NOT EXISTS (
						SELECT 1
						FROM finding_teams ft
						WHERE ft.finding_id = f.id
					)
				) AS critical_without_owner
			FROM organizations o
			LEFT JOIN repositories r ON r.org_id = o.id
			LEFT JOIN manifests m ON m.repo_id = r.id
			LEFT JOIN findings f ON f.manifest_id = m.id
			GROUP BY o.tenant_id
		)
		INSERT INTO tenant_metrics_daily (
			tenant_id,
			snapshot_date,
			open_critical,
			open_high,
			open_total,
			mttr_high_plus_hours,
			sla_breach_rate,
			scan_coverage_rate,
			critical_without_owner
		)
		SELECT
			t.id AS tenant_id,
			$1::date AS snapshot_date,
			COALESCE(tf.open_critical, 0) AS open_critical,
			COALESCE(tf.open_high, 0) AS open_high,
			COALESCE(tf.open_total, 0) AS open_total,
			COALESCE(tf.mttr_high_plus_hours, 0) AS mttr_high_plus_hours,
			COALESCE(
				tf.open_high_plus_sla_breach::numeric / NULLIF((COALESCE(tf.open_critical, 0) + COALESCE(tf.open_high, 0))::numeric, 0),
				0
			) AS sla_breach_rate,
			COALESCE(
				COALESCE(tr.scanned_repos_30d, 0)::numeric / NULLIF(COALESCE(tr.total_repos, 0)::numeric, 0),
				0
			) AS scan_coverage_rate,
			COALESCE(tf.critical_without_owner, 0) AS critical_without_owner
		FROM tenants t
		LEFT JOIN tenant_repos tr ON tr.tenant_id = t.id
		LEFT JOIN tenant_findings tf ON tf.tenant_id = t.id
		ON CONFLICT (tenant_id, snapshot_date)
		DO UPDATE SET
			open_critical = EXCLUDED.open_critical,
			open_high = EXCLUDED.open_high,
			open_total = EXCLUDED.open_total,
			mttr_high_plus_hours = EXCLUDED.mttr_high_plus_hours,
			sla_breach_rate = EXCLUDED.sla_breach_rate,
			scan_coverage_rate = EXCLUDED.scan_coverage_rate,
			critical_without_owner = EXCLUDED.critical_without_owner
	`, snapshotDate.Format(time.DateOnly))
	if err != nil {
		return 0, fmt.Errorf("upsert daily metrics snapshot: %w", err)
	}
	return tag.RowsAffected(), nil
}
