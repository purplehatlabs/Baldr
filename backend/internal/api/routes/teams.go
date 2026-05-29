package routes

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"go.uber.org/zap"
)

type TeamsHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewTeamsHandler(db *pgxpool.Pool, log *zap.Logger) *TeamsHandler {
	return &TeamsHandler{db: db, log: log}
}

func (h *TeamsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/teams", authMW)
	g.GET("", h.list)
	g.GET("/:id/members", h.members)
	g.GET("/:id/findings", h.findings)
}

type teamSummary struct {
	ID             string `json:"id"`
	OrgID          string `json:"org_id"`
	GithubTeamSlug string `json:"github_team_slug"`
	DisplayName    string `json:"display_name"`
	Critical       int    `json:"critical"`
	High           int    `json:"high"`
	Medium         int    `json:"medium"`
	Low            int    `json:"low"`
	Total          int    `json:"total"`
}

func (h *TeamsHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			t.id, t.org_id, t.github_team_slug, t.display_name,
			COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status = 'open') AS critical,
			COUNT(f.id) FILTER (WHERE f.severity = 'high'     AND f.status = 'open') AS high,
			COUNT(f.id) FILTER (WHERE f.severity = 'medium'   AND f.status = 'open') AS medium,
			COUNT(f.id) FILTER (WHERE f.severity = 'low'      AND f.status = 'open') AS low,
			COUNT(f.id) FILTER (WHERE f.status = 'open') AS total
		FROM teams t
		JOIN organizations o ON o.id = t.org_id
		LEFT JOIN finding_teams ft ON ft.team_id = t.id
		LEFT JOIN findings f ON f.id = ft.finding_id
		WHERE o.tenant_id = $1
		GROUP BY t.id, t.org_id, t.github_team_slug, t.display_name
		ORDER BY total DESC, t.display_name`,
		claims.TenantID,
	)
	if err != nil {
		h.log.Error("list teams", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var teams []teamSummary
	for rows.Next() {
		var t teamSummary
		if err := rows.Scan(&t.ID, &t.OrgID, &t.GithubTeamSlug, &t.DisplayName,
			&t.Critical, &t.High, &t.Medium, &t.Low, &t.Total); err != nil {
			continue
		}
		teams = append(teams, t)
	}
	if teams == nil {
		teams = []teamSummary{}
	}
	c.JSON(http.StatusOK, teams)
}

func (h *TeamsHandler) members(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	teamID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var teamOK bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS (
			SELECT 1
			FROM teams t
			JOIN organizations o ON o.id = t.org_id
			WHERE t.id = $1 AND o.tenant_id = $2
		)`, teamID, claims.TenantID,
	).Scan(&teamOK)
	if err != nil {
		h.log.Error("team members tenant check", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if !teamOK {
		c.JSON(http.StatusNotFound, gin.H{"error": "team not found"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT om.id, om.github_login, om.name, om.avatar_url, om.user_id, om.is_active
		FROM team_members tm
		JOIN org_members om ON om.id = tm.org_member_id
		JOIN teams t ON t.id = tm.team_id
		JOIN organizations o ON o.id = t.org_id
		WHERE tm.team_id = $1 AND o.tenant_id = $2 AND om.is_active = TRUE
		ORDER BY om.github_login`,
		teamID, claims.TenantID,
	)
	if err != nil {
		h.log.Error("team members query", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	type memberRow struct {
		ID          string     `json:"id"`
		GithubLogin string     `json:"github_login"`
		Name        string     `json:"name"`
		AvatarURL   string     `json:"avatar_url"`
		UserID      *uuid.UUID `json:"user_id,omitempty"`
		IsActive    bool       `json:"is_active"`
	}

	var members []memberRow
	for rows.Next() {
		var m memberRow
		if err := rows.Scan(
			&m.ID, &m.GithubLogin, &m.Name, &m.AvatarURL, &m.UserID, &m.IsActive,
		); err != nil {
			h.log.Warn("scan team member row", zap.Error(err))
			continue
		}
		members = append(members, m)
	}
	if members == nil {
		members = []memberRow{}
	}
	c.JSON(http.StatusOK, members)
}

func (h *TeamsHandler) findings(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	teamID := c.Param("id")

	// severity_rank orders criticality numerically; the text column would sort
	// alphabetically (critical, high, low, medium) which is wrong for the UI.
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT f.id, f.scan_job_id, f.manifest_id, f.osv_id, f.package_name,
		       f.package_version, f.fixed_version, f.severity, f.cvss_score,
		       f.summary, f.details, f.status, f.first_seen_at, f.last_seen_at,
		       r.full_name, m.path
		FROM findings f
		JOIN finding_teams ft ON ft.finding_id = f.id
		JOIN manifests m ON m.id = f.manifest_id
		JOIN repositories r ON r.id = m.repo_id
		JOIN organizations o ON o.id = r.org_id
		WHERE ft.team_id = $1 AND o.tenant_id = $2 AND f.status = 'open'
		ORDER BY CASE f.severity
			WHEN 'critical' THEN 0
			WHEN 'high'     THEN 1
			WHEN 'medium'   THEN 2
			WHEN 'low'      THEN 3
			ELSE 4
		END, f.last_seen_at DESC
		LIMIT 200`,
		teamID, claims.TenantID,
	)
	if err != nil {
		h.log.Error("team findings query", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	type row struct {
		ID             string    `json:"id"`
		ScanJobID      string    `json:"scan_job_id"`
		ManifestID     string    `json:"manifest_id"`
		OSVID          string    `json:"osv_id"`
		PackageName    string    `json:"package_name"`
		PackageVersion string    `json:"package_version"`
		FixedVersion   *string   `json:"fixed_version"`
		Severity       string    `json:"severity"`
		CVSSScore      *float64  `json:"cvss_score"`
		Summary        string    `json:"summary"`
		Details        string    `json:"details"`
		Status         string    `json:"status"`
		FirstSeenAt    time.Time `json:"first_seen_at"`
		LastSeenAt     time.Time `json:"last_seen_at"`
		RepoFullName   string    `json:"repo_full_name"`
		ManifestPath   string    `json:"manifest_path"`
	}

	var findings []row
	for rows.Next() {
		var f row
		if err := rows.Scan(
			&f.ID, &f.ScanJobID, &f.ManifestID, &f.OSVID, &f.PackageName,
			&f.PackageVersion, &f.FixedVersion, &f.Severity, &f.CVSSScore,
			&f.Summary, &f.Details, &f.Status, &f.FirstSeenAt, &f.LastSeenAt,
			&f.RepoFullName, &f.ManifestPath,
		); err != nil {
			h.log.Warn("scan team finding row", zap.Error(err))
			continue
		}
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []row{}
	}
	c.JSON(http.StatusOK, findings)
}
