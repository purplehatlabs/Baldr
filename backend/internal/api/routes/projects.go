package routes

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"go.uber.org/zap"
)

type ProjectsHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewProjectsHandler(db *pgxpool.Pool, log *zap.Logger) *ProjectsHandler {
	return &ProjectsHandler{db: db, log: log}
}

func (h *ProjectsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/projects", authMW)
	g.GET("", h.list)
	g.GET("/:id", h.get)
}

type projectSignals struct {
	ID            uuid.UUID  `json:"id"`
	Repo          string     `json:"repo"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
	OpenCritical  int        `json:"open_critical"`
	OpenHigh      int        `json:"open_high"`
	OpenTotal     int        `json:"open_total"`
}

type projectsListResponse struct {
	Items   []projectSignals `json:"items"`
	Page    int              `json:"page"`
	PerPage int              `json:"per_page"`
	Total   int              `json:"total"`
}

func (h *ProjectsHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	page, perPage, err := parsePageParams(c, 20, 100)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	offset := (page - 1) * perPage

	var total int
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT COUNT(*)
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		WHERE o.tenant_id = $1 AND r.is_archived = FALSE`,
		claims.TenantID,
	).Scan(&total)
	if err != nil {
		h.log.Error("projects total", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			r.id,
			r.full_name,
			r.last_scanned_at,
			COALESCE(COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'critical'), 0) AS open_critical,
			COALESCE(COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'high'), 0) AS open_high,
			COALESCE(COUNT(*) FILTER (WHERE f.status = 'open'), 0) AS open_total
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		LEFT JOIN manifests m ON m.repo_id = r.id
		LEFT JOIN findings f ON f.manifest_id = m.id
		WHERE o.tenant_id = $1 AND r.is_archived = FALSE
		GROUP BY r.id, r.full_name, r.last_scanned_at
		ORDER BY r.full_name
		LIMIT $2 OFFSET $3`,
		claims.TenantID, perPage, offset,
	)
	if err != nil {
		h.log.Error("projects list", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	items := make([]projectSignals, 0, perPage)
	for rows.Next() {
		var p projectSignals
		if err := rows.Scan(
			&p.ID,
			&p.Repo,
			&p.LastScannedAt,
			&p.OpenCritical,
			&p.OpenHigh,
			&p.OpenTotal,
		); err != nil {
			continue
		}
		items = append(items, p)
	}

	c.JSON(http.StatusOK, projectsListResponse{
		Items:   items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

type projectSummaryResponse struct {
	ID            uuid.UUID  `json:"id"`
	Repo          string     `json:"repo"`
	DefaultBranch string     `json:"default_branch"`
	IsArchived    bool       `json:"is_archived"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
	OpenCritical  int        `json:"open_critical"`
	OpenHigh      int        `json:"open_high"`
	OpenTotal     int        `json:"open_total"`
	FixedTotal    int        `json:"fixed_total"`
}

func (h *ProjectsHandler) get(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var resp projectSummaryResponse
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT
			r.id,
			r.full_name,
			r.default_branch,
			r.is_archived,
			r.last_scanned_at,
			COALESCE(COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'critical'), 0) AS open_critical,
			COALESCE(COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'high'), 0) AS open_high,
			COALESCE(COUNT(*) FILTER (WHERE f.status = 'open'), 0) AS open_total,
			COALESCE(COUNT(*) FILTER (WHERE f.status = 'fixed'), 0) AS fixed_total
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		LEFT JOIN manifests m ON m.repo_id = r.id
		LEFT JOIN findings f ON f.manifest_id = m.id
		WHERE o.tenant_id = $1 AND r.id = $2
		GROUP BY r.id, r.full_name, r.default_branch, r.is_archived, r.last_scanned_at`,
		claims.TenantID, projectID,
	).Scan(
		&resp.ID,
		&resp.Repo,
		&resp.DefaultBranch,
		&resp.IsArchived,
		&resp.LastScannedAt,
		&resp.OpenCritical,
		&resp.OpenHigh,
		&resp.OpenTotal,
		&resp.FixedTotal,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func parsePageParams(c *gin.Context, defaultPerPage int, maxPerPage int) (int, int, error) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		return 0, 0, fmt.Errorf("invalid page")
	}

	perPage, err := strconv.Atoi(c.DefaultQuery("per_page", strconv.Itoa(defaultPerPage)))
	if err != nil || perPage < 1 || perPage > maxPerPage {
		return 0, 0, fmt.Errorf("invalid per_page")
	}

	return page, perPage, nil
}
