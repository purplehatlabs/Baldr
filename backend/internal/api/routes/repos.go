package routes

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/models"
	repositoriesvc "github.com/purplehatlabs/Baldr/internal/repositories"
	"github.com/purplehatlabs/Baldr/internal/scheduler"
	"go.uber.org/zap"
)

type ReposHandler struct {
	db        *pgxpool.Pool
	scheduler *scheduler.OrgScheduler
	log       *zap.Logger
}

func NewReposHandler(db *pgxpool.Pool, sched *scheduler.OrgScheduler, log *zap.Logger) *ReposHandler {
	return &ReposHandler{db: db, scheduler: sched, log: log}
}

func (h *ReposHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/repos", authMW)
	g.GET("", h.list)
	g.POST("/rescan-all", h.rescanAll)
	g.POST("/:id/scan", h.triggerScan)
	g.PATCH("/:id/exposure", h.updateExposure)
	g.GET("/:id/jobs", h.listJobs)
}

const repoListSelect = `
			SELECT r.id, r.org_id, r.github_repo_id, r.full_name, r.default_branch,
			       r.is_archived, r.is_monorepo, r.is_internet_exposed, r.exposure_source,
			       r.exposure_updated_at, r.asset_criticality, r.data_sensitivity, r.environment,
			       r.last_scanned_at, r.created_at,
			       COALESCE(
			         (SELECT j.status::text FROM scan_jobs j
			          WHERE j.repo_id = r.id
			          ORDER BY j.created_at DESC
			          LIMIT 1),
			         CASE WHEN r.last_scanned_at IS NOT NULL THEN 'completed' END
			       ) AS latest_scan_status`

func (h *ReposHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	orgIDStr := c.Query("org_id")
	exposureStatus := c.Query("exposure_status")

	var rows interface {
		Next() bool
		Scan(...any) error
		Close()
	}
	var err error

	if orgIDStr != "" {
		orgID, parseErr := uuid.Parse(orgIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid org_id"})
			return
		}
		rows, err = h.db.Query(c.Request.Context(), repoListSelect+`
			FROM repositories r
			JOIN organizations o ON o.id = r.org_id
			WHERE o.tenant_id = $1 AND r.org_id = $2 `+exposureFilterSQL(exposureStatus)+`
			ORDER BY r.full_name`,
			claims.TenantID, orgID,
		)
	} else {
		rows, err = h.db.Query(c.Request.Context(), repoListSelect+`
			FROM repositories r
			JOIN organizations o ON o.id = r.org_id
			WHERE o.tenant_id = $1 `+exposureFilterSQL(exposureStatus)+`
			ORDER BY r.full_name`,
			claims.TenantID,
		)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var repos []models.Repository
	for rows.Next() {
		var r models.Repository
		var latestStatus *string
		if err := rows.Scan(&r.ID, &r.OrgID, &r.GithubRepoID, &r.FullName,
			&r.DefaultBranch, &r.IsArchived, &r.IsMonorepo, &r.IsInternetExposed, &r.ExposureSource,
			&r.ExposureUpdatedAt, &r.AssetCriticality, &r.DataSensitivity, &r.Environment,
			&r.LastScannedAt, &r.CreatedAt, &latestStatus); err != nil {
			continue
		}
		if latestStatus != nil {
			status := models.ScanStatus(*latestStatus)
			r.LatestScanStatus = &status
		}
		repos = append(repos, r)
	}
	if repos == nil {
		repos = []models.Repository{}
	}
	c.JSON(http.StatusOK, repos)
}

func (h *ReposHandler) triggerScan(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	repoID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	err = repositoriesvc.EnsureRepoScannableForTenant(c.Request.Context(), h.db, repoID, claims.TenantID)
	if repositoriesvc.IsRepoMissingForTenant(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if respondScanEnqueueError(c, err) {
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := h.scheduler.EnqueueRepo(repoID, models.TriggerManual); err != nil {
		if respondScanEnqueueError(c, err) {
			return
		}
		h.log.Error("enqueue scan", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not enqueue scan"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"message": "scan enqueued"})
}

// rescanAll enqueues a scan task for every repository the tenant owns.
// Useful after a scanner upgrade (e.g. new severity mapping) to refresh
// findings without re-importing repos from GitHub.
func (h *ReposHandler) rescanAll(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	orgIDStr := c.Query("org_id")

	args := []any{claims.TenantID}
	query := `
		SELECT r.id
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		WHERE o.tenant_id = $1 AND r.is_archived = false`
	if orgIDStr != "" {
		orgID, err := uuid.Parse(orgIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid org_id"})
			return
		}
		query += ` AND r.org_id = $2`
		args = append(args, orgID)
	}

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}

	enqueued := 0
	blocked := make([]blockedRepo, 0)
	skipped := make([]blockedRepo, 0)
	for _, id := range ids {
		if err := h.scheduler.EnqueueRepo(id, models.TriggerManual); err != nil {
			if errors.Is(err, repositoriesvc.ErrScanBlockedMissingInternetExposure) {
				blocked = append(blocked, blockedRepo{
					RepoID: id.String(),
					Reason: "scan_blocked_missing_internet_exposure",
				})
				continue
			}
			if errors.Is(err, repositoriesvc.ErrScanAlreadyQueuedOrRunning) {
				skipped = append(skipped, blockedRepo{
					RepoID: id.String(),
					Reason: "scan_already_queued_or_running",
				})
				continue
			}
			h.log.Warn("rescan-all: enqueue failed", zap.String("repo_id", id.String()), zap.Error(err))
			continue
		}
		enqueued++
	}

	c.JSON(http.StatusAccepted, gin.H{
		"enqueued":      enqueued,
		"total":         len(ids),
		"blocked":       len(blocked),
		"blocked_repos": blocked,
		"skipped":       len(skipped),
		"skipped_repos": skipped,
	})
}

type blockedRepo struct {
	RepoID string `json:"repo_id"`
	Reason string `json:"reason"`
}

type updateExposureRequest struct {
	IsInternetExposed *bool   `json:"is_internet_exposed" binding:"required"`
	ExposureSource    string  `json:"exposure_source" binding:"required"`
	AssetCriticality  *string `json:"asset_criticality,omitempty"`
	DataSensitivity   *string `json:"data_sensitivity,omitempty"`
	Environment       *string `json:"environment,omitempty"`
}

func (h *ReposHandler) updateExposure(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	repoID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var req updateExposureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ExposureSource != "manual" && req.ExposureSource != "auto_discovery" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exposure_source"})
		return
	}
	if req.AssetCriticality != nil && !isValidAssetCriticality(*req.AssetCriticality) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset_criticality"})
		return
	}
	if req.DataSensitivity != nil && !isValidDataSensitivity(*req.DataSensitivity) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data_sensitivity"})
		return
	}
	if req.Environment != nil && !isValidEnvironment(*req.Environment) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid environment"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		UPDATE repositories r
		SET is_internet_exposed = $1,
		    exposure_source = $2,
		    asset_criticality = COALESCE($3, r.asset_criticality),
		    data_sensitivity = COALESCE($4, r.data_sensitivity),
		    environment = COALESCE($5, r.environment),
		    exposure_updated_at = NOW()
		FROM organizations o
		WHERE r.id = $6
		  AND o.id = r.org_id
		  AND o.tenant_id = $7`,
		*req.IsInternetExposed, req.ExposureSource, req.AssetCriticality, req.DataSensitivity, req.Environment, repoID, claims.TenantID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func isValidAssetCriticality(value string) bool {
	switch value {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func isValidDataSensitivity(value string) bool {
	switch value {
	case "public", "internal", "confidential", "restricted":
		return true
	default:
		return false
	}
}

func isValidEnvironment(value string) bool {
	switch value {
	case "dev", "staging", "prod":
		return true
	default:
		return false
	}
}

func (h *ReposHandler) listJobs(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	repoID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT j.id, j.repo_id, j.status, j.triggered_by, j.commit_sha,
		       j.started_at, j.completed_at, j.error_msg, j.created_at
		FROM scan_jobs j
		JOIN repositories r ON r.id = j.repo_id
		JOIN organizations o ON o.id = r.org_id
		WHERE j.repo_id = $1 AND o.tenant_id = $2
		ORDER BY j.created_at DESC
		LIMIT 50`,
		repoID, claims.TenantID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var jobs []models.ScanJob
	for rows.Next() {
		var j models.ScanJob
		if err := rows.Scan(&j.ID, &j.RepoID, &j.Status, &j.TriggeredBy,
			&j.CommitSHA, &j.StartedAt, &j.CompletedAt, &j.ErrorMsg, &j.CreatedAt); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	if jobs == nil {
		jobs = []models.ScanJob{}
	}
	c.JSON(http.StatusOK, jobs)
}

func exposureFilterSQL(status string) string {
	switch status {
	case "pending":
		return " AND r.is_internet_exposed IS NULL"
	case "internet":
		return " AND r.is_internet_exposed = TRUE"
	case "internal":
		return " AND r.is_internet_exposed = FALSE"
	default:
		return ""
	}
}
