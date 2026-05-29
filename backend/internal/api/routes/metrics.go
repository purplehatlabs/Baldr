package routes

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"go.uber.org/zap"
)

type MetricsHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewMetricsHandler(db *pgxpool.Pool, log *zap.Logger) *MetricsHandler {
	return &MetricsHandler{db: db, log: log}
}

func (h *MetricsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/metrics", authMW)
	g.GET("/overview", h.overview)
	g.GET("/trends", h.trends)
	g.GET("/risk-trend", h.riskTrend)
	g.GET("/risk-by-repo", h.riskByRepo)
	g.GET("/risk-by-team", h.riskByTeam)
}

type metricsOverviewResponse struct {
	OpenCritical         int     `json:"open_critical"`
	OpenHigh             int     `json:"open_high"`
	MTTRHighPlusHours    float64 `json:"mttr_high_plus_hours"`
	SLABreachRate        float64 `json:"sla_breach_rate"`
	ScanCoverageRate     float64 `json:"scan_coverage_rate"`
	CriticalWithoutOwner int     `json:"critical_without_owner"`
}

func (h *MetricsHandler) overview(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var resp metricsOverviewResponse
	err := h.db.QueryRow(c.Request.Context(), `
		WITH tenant_repos AS (
			SELECT r.id, r.last_scanned_at
			FROM repositories r
			JOIN organizations o ON o.id = r.org_id
			WHERE o.tenant_id = $1
				AND r.is_archived = FALSE
		),
		tenant_findings AS (
			SELECT f.id, f.severity, f.status, f.first_seen_at, f.last_seen_at
			FROM findings f
			WHERE f.tenant_id = $1
		),
		open_high_plus AS (
			SELECT COUNT(*) AS total
			FROM tenant_findings
			WHERE status = 'open' AND severity IN ('critical', 'high')
		),
		sla_breaches AS (
			SELECT COUNT(*) AS total
			FROM tenant_findings
			WHERE status = 'open'
				AND (
					(severity = 'critical' AND first_seen_at <= NOW() - INTERVAL '7 days')
					OR
					(severity = 'high' AND first_seen_at <= NOW() - INTERVAL '30 days')
				)
		)
		SELECT
			COALESCE(SUM(CASE WHEN tf.status = 'open' AND tf.severity = 'critical' THEN 1 ELSE 0 END), 0) AS open_critical,
			COALESCE(SUM(CASE WHEN tf.status = 'open' AND tf.severity = 'high' THEN 1 ELSE 0 END), 0) AS open_high,
			COALESCE(AVG(CASE
				WHEN tf.status = 'fixed' AND tf.severity IN ('critical', 'high') AND tf.last_seen_at >= tf.first_seen_at
				THEN EXTRACT(EPOCH FROM (tf.last_seen_at - tf.first_seen_at)) / 3600
			END), 0) AS mttr_high_plus_hours,
			COALESCE(
				(SELECT sb.total::numeric FROM sla_breaches sb)
				/
				NULLIF((SELECT ohp.total::numeric FROM open_high_plus ohp), 0),
				0
			) AS sla_breach_rate,
			COALESCE(
				(SELECT COUNT(*) FROM tenant_repos tr WHERE tr.last_scanned_at >= NOW() - INTERVAL '30 days')::numeric
				/
				NULLIF((SELECT COUNT(*)::numeric FROM tenant_repos), 0),
				0
			) AS scan_coverage_rate,
			COALESCE(SUM(CASE
				WHEN tf.status = 'open' AND tf.severity = 'critical' AND NOT EXISTS (
					SELECT 1 FROM finding_teams ft WHERE ft.finding_id = tf.id
				)
				THEN 1 ELSE 0
			END), 0) AS critical_without_owner
		FROM tenant_findings tf`,
		claims.TenantID,
	).Scan(
		&resp.OpenCritical,
		&resp.OpenHigh,
		&resp.MTTRHighPlusHours,
		&resp.SLABreachRate,
		&resp.ScanCoverageRate,
		&resp.CriticalWithoutOwner,
	)
	if err != nil {
		h.log.Error("metrics overview", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

type metricsTrendPoint struct {
	Date          string `json:"date"`
	NewFindings   int    `json:"new_findings"`
	FixedFindings int    `json:"fixed_findings"`
}

type metricsTrendsResponse struct {
	Days  int                 `json:"days"`
	Trend []metricsTrendPoint `json:"trend"`
}

func (h *MetricsHandler) trends(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	days, err := parseDaysQuery(c, 30, 365)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			TO_CHAR(day::date, 'YYYY-MM-DD') AS day,
			(
				SELECT COUNT(*)
				FROM findings f
				WHERE f.tenant_id = $1
					AND DATE(f.first_seen_at) = day::date
			) AS new_findings,
			(
				SELECT COUNT(*)
				FROM findings f
				WHERE f.tenant_id = $1
					AND f.status = 'fixed'
					AND DATE(f.last_seen_at) = day::date
			) AS fixed_findings
		FROM generate_series(
			CURRENT_DATE - ($2::int - 1) * INTERVAL '1 day',
			CURRENT_DATE,
			INTERVAL '1 day'
		) AS day
		ORDER BY day`,
		claims.TenantID, days,
	)
	if err != nil {
		h.log.Error("metrics trends", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	resp := metricsTrendsResponse{
		Days:  days,
		Trend: make([]metricsTrendPoint, 0, days),
	}
	for rows.Next() {
		var point metricsTrendPoint
		if err := rows.Scan(&point.Date, &point.NewFindings, &point.FixedFindings); err != nil {
			continue
		}
		resp.Trend = append(resp.Trend, point)
	}

	c.JSON(http.StatusOK, resp)
}

type riskTrendPoint struct {
	Date          string  `json:"date"`
	OpenCritical  int     `json:"open_critical"`
	OpenHigh      int     `json:"open_high"`
	SLABreachRate float64 `json:"sla_breach_rate"`
	NewFindings   int     `json:"new_findings"`
	FixedFindings int     `json:"fixed_findings"`
}

type riskTrendResponse struct {
	Days  int              `json:"days"`
	Trend []riskTrendPoint `json:"trend"`
}

func (h *MetricsHandler) riskTrend(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	days, err := parseDaysQuery(c, 30, 365)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			TO_CHAR(day::date, 'YYYY-MM-DD') AS day,
			COALESCE(tmd.open_critical, 0) AS open_critical,
			COALESCE(tmd.open_high, 0) AS open_high,
			COALESCE(tmd.sla_breach_rate, 0) AS sla_breach_rate,
			(
				SELECT COUNT(*)
				FROM findings f
				WHERE f.tenant_id = $1
					AND DATE(f.first_seen_at) = day::date
			) AS new_findings,
			(
				SELECT COUNT(*)
				FROM findings f
				WHERE f.tenant_id = $1
					AND f.status = 'fixed'
					AND DATE(f.last_seen_at) = day::date
			) AS fixed_findings
		FROM generate_series(
			CURRENT_DATE - ($2::int - 1) * INTERVAL '1 day',
			CURRENT_DATE,
			INTERVAL '1 day'
		) AS day
		LEFT JOIN tenant_metrics_daily tmd
			ON tmd.tenant_id = $1 AND tmd.snapshot_date = day::date
		ORDER BY day`,
		claims.TenantID, days,
	)
	if err != nil {
		h.log.Error("metrics risk trend", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	resp := riskTrendResponse{
		Days:  days,
		Trend: make([]riskTrendPoint, 0, days),
	}
	for rows.Next() {
		var point riskTrendPoint
		if err := rows.Scan(
			&point.Date,
			&point.OpenCritical,
			&point.OpenHigh,
			&point.SLABreachRate,
			&point.NewFindings,
			&point.FixedFindings,
		); err != nil {
			continue
		}
		resp.Trend = append(resp.Trend, point)
	}

	c.JSON(http.StatusOK, resp)
}

type repoRiskRow struct {
	RepoID            string  `json:"repo_id"`
	RepoFullName      string  `json:"repo_full_name"`
	IsInternetExposed *bool   `json:"is_internet_exposed"`
	OpenCritical      int     `json:"open_critical"`
	OpenHigh          int     `json:"open_high"`
	OpenTotal         int     `json:"open_total"`
	MaxRiskScore      float64 `json:"max_risk_score"`
	SLABreachCount    int     `json:"sla_breach_count"`
	ReachableCount    int     `json:"reachable_count"`
}

type riskByRepoResponse struct {
	Items []repoRiskRow `json:"items"`
}

func (h *MetricsHandler) riskByRepo(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	limit, err := parseLimitQuery(c, 10, 50)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			r.id::text,
			r.full_name,
			r.is_internet_exposed,
			COALESCE(COUNT(f.id) FILTER (WHERE f.status = 'open' AND f.severity = 'critical'), 0) AS open_critical,
			COALESCE(COUNT(f.id) FILTER (WHERE f.status = 'open' AND f.severity = 'high'), 0) AS open_high,
			COALESCE(COUNT(f.id) FILTER (WHERE f.status = 'open'), 0) AS open_total,
			COALESCE(MAX(f.risk_score) FILTER (WHERE f.status = 'open'), 0) AS max_risk_score,
			COALESCE(COUNT(f.id) FILTER (WHERE f.status = 'open' AND f.is_sla_breached = TRUE), 0) AS sla_breach_count,
			COALESCE(COUNT(f.id) FILTER (WHERE f.status = 'open' AND f.reachability_status = 'reachable'), 0) AS reachable_count
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		LEFT JOIN manifests m ON m.repo_id = r.id
		LEFT JOIN findings f ON f.manifest_id = m.id
		WHERE o.tenant_id = $1
			AND r.is_archived = FALSE
		GROUP BY r.id, r.full_name, r.is_internet_exposed
		HAVING COALESCE(COUNT(f.id) FILTER (WHERE f.status = 'open'), 0) > 0
		ORDER BY max_risk_score DESC, open_critical DESC, sla_breach_count DESC
		LIMIT $2`,
		claims.TenantID, limit,
	)
	if err != nil {
		h.log.Error("metrics risk by repo", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	resp := riskByRepoResponse{Items: make([]repoRiskRow, 0, limit)}
	for rows.Next() {
		var row repoRiskRow
		if err := rows.Scan(
			&row.RepoID,
			&row.RepoFullName,
			&row.IsInternetExposed,
			&row.OpenCritical,
			&row.OpenHigh,
			&row.OpenTotal,
			&row.MaxRiskScore,
			&row.SLABreachCount,
			&row.ReachableCount,
		); err != nil {
			continue
		}
		resp.Items = append(resp.Items, row)
	}

	c.JSON(http.StatusOK, resp)
}

type teamRiskRow struct {
	TeamID         string  `json:"team_id"`
	TeamSlug       string  `json:"team_slug"`
	DisplayName    string  `json:"display_name"`
	OpenCritical   int     `json:"open_critical"`
	OpenHigh       int     `json:"open_high"`
	OpenTotal      int     `json:"open_total"`
	MaxRiskScore   float64 `json:"max_risk_score"`
	SLABreachCount int     `json:"sla_breach_count"`
	SLABreachRate  float64 `json:"sla_breach_rate"`
}

type riskByTeamResponse struct {
	Items []teamRiskRow `json:"items"`
}

func (h *MetricsHandler) riskByTeam(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	limit, err := parseLimitQuery(c, 10, 50)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			t.id::text,
			t.github_team_slug,
			t.display_name,
			COALESCE(COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open' AND f.severity = 'critical'), 0) AS open_critical,
			COALESCE(COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open' AND f.severity = 'high'), 0) AS open_high,
			COALESCE(COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open'), 0) AS open_total,
			COALESCE(MAX(f.risk_score) FILTER (WHERE f.status = 'open'), 0) AS max_risk_score,
			COALESCE(COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open' AND f.is_sla_breached = TRUE), 0) AS sla_breach_count,
			COALESCE(
				COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open' AND f.is_sla_breached = TRUE)::numeric
				/ NULLIF(COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open' AND f.severity IN ('critical', 'high')), 0),
				0
			) AS sla_breach_rate
		FROM teams t
		JOIN organizations o ON o.id = t.org_id
		LEFT JOIN finding_teams ft ON ft.team_id = t.id
		LEFT JOIN findings f ON f.id = ft.finding_id
		WHERE o.tenant_id = $1
		GROUP BY t.id, t.github_team_slug, t.display_name
		HAVING COALESCE(COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open'), 0) > 0
		ORDER BY max_risk_score DESC, open_critical DESC, sla_breach_count DESC
		LIMIT $2`,
		claims.TenantID, limit,
	)
	if err != nil {
		h.log.Error("metrics risk by team", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	resp := riskByTeamResponse{Items: make([]teamRiskRow, 0, limit)}
	for rows.Next() {
		var row teamRiskRow
		if err := rows.Scan(
			&row.TeamID,
			&row.TeamSlug,
			&row.DisplayName,
			&row.OpenCritical,
			&row.OpenHigh,
			&row.OpenTotal,
			&row.MaxRiskScore,
			&row.SLABreachCount,
			&row.SLABreachRate,
		); err != nil {
			continue
		}
		resp.Items = append(resp.Items, row)
	}

	c.JSON(http.StatusOK, resp)
}

func parseLimitQuery(c *gin.Context, defaultLimit int, maxLimit int) (int, error) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", strconv.Itoa(defaultLimit)))
	if err != nil {
		return 0, fmt.Errorf("invalid limit")
	}
	if limit < 1 || limit > maxLimit {
		return 0, fmt.Errorf("invalid limit")
	}
	return limit, nil
}

func parseDaysQuery(c *gin.Context, defaultDays int, maxDays int) (int, error) {
	days, err := strconv.Atoi(c.DefaultQuery("days", strconv.Itoa(defaultDays)))
	if err != nil {
		return 0, fmt.Errorf("invalid days")
	}
	if days < 1 || days > maxDays {
		return 0, fmt.Errorf("invalid days")
	}
	return days, nil
}
