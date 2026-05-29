package routes

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type ScanJobsHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewScanJobsHandler(db *pgxpool.Pool, log *zap.Logger) *ScanJobsHandler {
	return &ScanJobsHandler{db: db, log: log}
}

func (h *ScanJobsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/scan-jobs", authMW)
	g.GET("", h.list)
	g.GET("/summary", h.summary)
}

type scanJobsListResponse struct {
	Items   []models.ScanJobWithRepo `json:"items"`
	Page    int                      `json:"page"`
	PerPage int                      `json:"per_page"`
	Total   int                      `json:"total"`
}

type scanJobsSummaryResponse struct {
	Pending     int `json:"pending"`
	Running     int `json:"running"`
	TotalActive int `json:"total_active"`
}

func (h *ScanJobsHandler) summary(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var summary scanJobsSummaryResponse
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT
			COALESCE(COUNT(*) FILTER (WHERE j.status = 'pending'), 0),
			COALESCE(COUNT(*) FILTER (WHERE j.status = 'running'), 0)
		FROM scan_jobs j
		JOIN repositories r ON r.id = j.repo_id
		JOIN organizations o ON o.id = r.org_id
		WHERE o.tenant_id = $1`,
		claims.TenantID,
	).Scan(&summary.Pending, &summary.Running)
	if err != nil {
		h.log.Error("scan jobs summary", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	summary.TotalActive = summary.Pending + summary.Running
	c.JSON(http.StatusOK, summary)
}

func (h *ScanJobsHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	page, perPage, err := parsePageParams(c, 50, 200)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	offset := (page - 1) * perPage

	status := c.Query("status")
	if status != "" && !isValidScanStatus(status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}

	var repoID *uuid.UUID
	if repoIDStr := c.Query("repo_id"); repoIDStr != "" {
		parsed, parseErr := uuid.Parse(repoIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_id"})
			return
		}
		repoID = &parsed
	}

	args := []any{claims.TenantID}
	filter := `
		FROM scan_jobs j
		JOIN repositories r ON r.id = j.repo_id
		JOIN organizations o ON o.id = r.org_id
		WHERE o.tenant_id = $1`

	if status != "" {
		args = append(args, status)
		filter += fmt.Sprintf(` AND j.status = $%d`, len(args))
	}
	if repoID != nil {
		args = append(args, *repoID)
		filter += fmt.Sprintf(` AND j.repo_id = $%d`, len(args))
	}

	var total int
	countQuery := `SELECT COUNT(*) ` + filter
	if err := h.db.QueryRow(c.Request.Context(), countQuery, args...).Scan(&total); err != nil {
		h.log.Error("scan jobs count", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	listArgs := append(append([]any{}, args...), perPage, offset)
	listQuery := `
		SELECT j.id, j.repo_id, j.status, j.triggered_by, j.commit_sha,
		       j.started_at, j.completed_at, j.error_msg, j.created_at,
		       r.full_name ` + filter + `
		ORDER BY j.created_at DESC
		LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)

	rows, err := h.db.Query(c.Request.Context(), listQuery, listArgs...)
	if err != nil {
		h.log.Error("scan jobs list", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	items := make([]models.ScanJobWithRepo, 0, perPage)
	for rows.Next() {
		var item models.ScanJobWithRepo
		if err := rows.Scan(
			&item.ID, &item.RepoID, &item.Status, &item.TriggeredBy, &item.CommitSHA,
			&item.StartedAt, &item.CompletedAt, &item.ErrorMsg, &item.CreatedAt,
			&item.RepoFullName,
		); err != nil {
			continue
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, scanJobsListResponse{
		Items:   items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

func isValidScanStatus(status string) bool {
	switch models.ScanStatus(status) {
	case models.ScanPending, models.ScanRunning, models.ScanCompleted, models.ScanFailed:
		return true
	default:
		return false
	}
}
