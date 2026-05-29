package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"go.uber.org/zap"
)

type DashboardHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewDashboardHandler(db *pgxpool.Pool, log *zap.Logger) *DashboardHandler {
	return &DashboardHandler{db: db, log: log}
}

func (h *DashboardHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	r.GET("/api/v1/dashboard", authMW, h.summary)
}

type dashboardSummary struct {
	FindingsBySeveity map[string]int `json:"findings_by_severity"`
	TotalRepos        int            `json:"total_repos"`
	TotalFindings     int            `json:"total_findings"`
	OpenFindings      int            `json:"open_findings"`
	FixedFindings     int            `json:"fixed_findings"`
}

func (h *DashboardHandler) summary(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	summary := dashboardSummary{
		FindingsBySeveity: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"unknown":  0,
		},
	}

	// Count repos
	_ = h.db.QueryRow(c.Request.Context(), `
		SELECT COUNT(*) FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		WHERE o.tenant_id = $1 AND r.is_archived = FALSE`,
		claims.TenantID,
	).Scan(&summary.TotalRepos)

	// Count findings by severity (open only)
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT f.severity, COUNT(*)
		FROM findings f
		WHERE f.tenant_id = $1 AND f.status = 'open'
		GROUP BY f.severity`,
		claims.TenantID,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var count int
			if err := rows.Scan(&sev, &count); err == nil {
				summary.FindingsBySeveity[sev] = count
				summary.OpenFindings += count
			}
		}
	}

	for _, v := range summary.FindingsBySeveity {
		summary.TotalFindings += v
	}

	// Count fixed
	_ = h.db.QueryRow(c.Request.Context(), `
		SELECT COUNT(*) FROM findings f
		WHERE f.tenant_id = $1 AND f.status = 'fixed'`,
		claims.TenantID,
	).Scan(&summary.FixedFindings)

	c.JSON(http.StatusOK, summary)
}
