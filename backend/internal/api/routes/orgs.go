package routes

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/membership"
	"github.com/purplehatlabs/Baldr/internal/models"
	"github.com/purplehatlabs/Baldr/internal/queue"
	repositoriesvc "github.com/purplehatlabs/Baldr/internal/repositories"
	"github.com/purplehatlabs/Baldr/internal/scheduler"
	"go.uber.org/zap"
)

type OrgsHandler struct {
	db                *pgxpool.Pool
	github            *githubclient.Client
	scheduler         *scheduler.OrgScheduler
	enqueuer          *queue.Enqueuer
	membership        *membership.Service
	membershipEnabled bool
	log               *zap.Logger
}

func NewOrgsHandler(
	db *pgxpool.Pool,
	gh *githubclient.Client,
	sched *scheduler.OrgScheduler,
	enqueuer *queue.Enqueuer,
	membershipEnabled bool,
	log *zap.Logger,
) *OrgsHandler {
	return &OrgsHandler{
		db:                db,
		github:            gh,
		scheduler:         sched,
		enqueuer:          enqueuer,
		membership:        membership.NewService(db, gh, log),
		membershipEnabled: membershipEnabled,
		log:               log,
	}
}

func (h *OrgsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/orgs", authMW)
	g.GET("", h.list)
	g.POST("", h.create)
	g.DELETE("/:id", h.delete)
	g.GET("/:id/github-repos", h.browseGitHubRepos)
	g.POST("/:id/github-repos/scan", h.scanGitHubRepo)
	g.POST("/:id/github-repos/scan-batch", h.scanGitHubReposBatch)
	g.POST("/:id/sync", h.syncOrgRepos)
	g.POST("/:id/sync-memberships", h.syncMemberships)
}

const maxBatchScan = 200

// classifyGitHubError maps github client errors to user-facing (status, message)
// pairs. Returns (0, "") when the error doesn't match a known category, so the
// caller can fall back to a generic 502.
func classifyGitHubError(err error) (int, string) {
	switch {
	case errors.Is(err, githubclient.ErrNoTenantConfig):
		return http.StatusBadRequest,
			"Upload your GitHub App PEM in Settings before using this feature."
	case errors.Is(err, githubclient.ErrInstallationNotFound):
		return http.StatusBadRequest,
			"GitHub returned 404 for this installation. Common causes: " +
				"(1) the Installation ID saved for this org doesn't belong to the App you uploaded, " +
				"(2) the App ID and Installation ID were swapped (they are different numbers), or " +
				"(3) the App was uninstalled. " +
				"Check both values at github.com/settings/apps/<your-app>/installations."
	}
	return 0, ""
}

func (h *OrgsHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, tenant_id, github_org_login, github_app_installation_id, scan_cron, is_active, created_at
		FROM organizations WHERE tenant_id = $1 ORDER BY created_at DESC`,
		claims.TenantID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var orgs []models.Organization
	for rows.Next() {
		var o models.Organization
		if err := rows.Scan(&o.ID, &o.TenantID, &o.GithubOrgLogin,
			&o.GithubAppInstallationID, &o.ScanCron, &o.IsActive, &o.CreatedAt); err != nil {
			continue
		}
		orgs = append(orgs, o)
	}
	if orgs == nil {
		orgs = []models.Organization{}
	}
	c.JSON(http.StatusOK, orgs)
}

type createOrgRequest struct {
	GithubOrgLogin          string `json:"github_org_login" binding:"required"`
	GithubAppInstallationID *int64 `json:"github_app_installation_id"`
	ScanCron                string `json:"scan_cron"`
}

func (h *OrgsHandler) create(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req createOrgRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cron := req.ScanCron
	if cron == "" {
		cron = "0 2 * * *"
	}

	org := models.Organization{
		ID:                      uuid.New(),
		TenantID:                claims.TenantID,
		GithubOrgLogin:          req.GithubOrgLogin,
		GithubAppInstallationID: req.GithubAppInstallationID,
		ScanCron:                cron,
		IsActive:                true,
		CreatedAt:               time.Now(),
	}

	_, err := h.db.Exec(c.Request.Context(), `
		INSERT INTO organizations (id, tenant_id, github_org_login, github_app_installation_id, scan_cron, is_active, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		org.ID, org.TenantID, org.GithubOrgLogin, org.GithubAppInstallationID,
		org.ScanCron, org.IsActive, org.CreatedAt,
	)
	if err != nil {
		h.log.Error("create org", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create org"})
		return
	}

	c.JSON(http.StatusCreated, org)
}

func (h *OrgsHandler) delete(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM organizations WHERE id=$1 AND tenant_id=$2`,
		orgID, claims.TenantID,
	)
	if err != nil || result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// loadOrgForTenant fetches an org owned by the caller's tenant and validates it
// has a GitHub App installation. Writes the proper HTTP error on failure.
func (h *OrgsHandler) loadOrgForTenant(c *gin.Context, orgID uuid.UUID) (*models.Organization, bool) {
	claims := middleware.ClaimsFrom(c)

	var org models.Organization
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, tenant_id, github_org_login, github_app_installation_id,
		       scan_cron, is_active, created_at
		FROM organizations
		WHERE id = $1 AND tenant_id = $2`,
		orgID, claims.TenantID,
	).Scan(&org.ID, &org.TenantID, &org.GithubOrgLogin,
		&org.GithubAppInstallationID, &org.ScanCron, &org.IsActive, &org.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "org not found"})
		return nil, false
	}
	if org.GithubAppInstallationID == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "org has no GitHub App installation_id; set it in Settings",
		})
		return nil, false
	}
	return &org, true
}

type githubRepoDTO struct {
	GithubRepoID      int64      `json:"github_repo_id"`
	FullName          string     `json:"full_name"`
	Description       string     `json:"description"`
	DefaultBranch     string     `json:"default_branch"`
	Private           bool       `json:"private"`
	Language          string     `json:"language"`
	UpdatedAt         time.Time  `json:"updated_at"`
	IsTracked         bool       `json:"is_tracked"`
	TrackedRepoID     *uuid.UUID `json:"tracked_repo_id,omitempty"`
	LastScannedAt     *time.Time `json:"last_scanned_at,omitempty"`
	LatestScanStatus  *string    `json:"latest_scan_status,omitempty"`
	IsInternetExposed *bool      `json:"is_internet_exposed,omitempty"`
}

type browsePage struct {
	Repos    []githubRepoDTO `json:"repos"`
	Page     int             `json:"page"`
	PerPage  int             `json:"per_page"`
	NextPage int             `json:"next_page"`
}

// loadTrackedRepos returns a lookup of {github_repo_id → tracked repo metadata}
// for repos already in our DB for this org. Used to annotate browse listings.
func (h *OrgsHandler) loadTrackedRepos(
	c *gin.Context, orgID uuid.UUID,
) map[int64]struct {
	ID                uuid.UUID
	LastScannedAt     *time.Time
	LatestScanStatus  *string
	IsInternetExposed *bool
} {
	out := map[int64]struct {
		ID                uuid.UUID
		LastScannedAt     *time.Time
		LatestScanStatus  *string
		IsInternetExposed *bool
	}{}
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT r.id, r.github_repo_id, r.last_scanned_at, r.is_internet_exposed,
		       COALESCE(
		         (SELECT j.status::text FROM scan_jobs j
		          WHERE j.repo_id = r.id
		          ORDER BY j.created_at DESC
		          LIMIT 1),
		         CASE WHEN r.last_scanned_at IS NOT NULL THEN 'completed' END
		       ) AS latest_scan_status
		FROM repositories r
		WHERE r.org_id = $1`, orgID,
	)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var ghID int64
		var last *time.Time
		var isInternetExposed *bool
		var latestStatus *string
		if err := rows.Scan(&id, &ghID, &last, &isInternetExposed, &latestStatus); err != nil {
			continue
		}
		out[ghID] = struct {
			ID                uuid.UUID
			LastScannedAt     *time.Time
			LatestScanStatus  *string
			IsInternetExposed *bool
		}{id, last, latestStatus, isInternetExposed}
	}
	return out
}

// browseGitHubRepos lists repositories live from the GitHub API for the given
// org, paginated. Query params: ?page (default 1) and ?per_page (default 50,
// max 100). Each entry is annotated with the tracked state from our DB.
func (h *OrgsHandler) browseGitHubRepos(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	org, ok := h.loadOrgForTenant(c, orgID)
	if !ok {
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))

	repos, nextPage, err := h.github.ListOrgReposPage(c.Request.Context(),
		claims.TenantID, *org.GithubAppInstallationID, org.GithubOrgLogin,
		page, perPage)
	if err != nil {
		if status, msg := classifyGitHubError(err); status > 0 {
			c.JSON(status, gin.H{"error": msg})
			return
		}
		h.log.Error("list github repos", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not list repos from GitHub: " + err.Error()})
		return
	}

	tracked := h.loadTrackedRepos(c, org.ID)

	dtos := make([]githubRepoDTO, 0, len(repos))
	for _, r := range repos {
		dto := githubRepoDTO{
			GithubRepoID:  r.GetID(),
			FullName:      r.GetFullName(),
			Description:   r.GetDescription(),
			DefaultBranch: r.GetDefaultBranch(),
			Private:       r.GetPrivate(),
			Language:      r.GetLanguage(),
			UpdatedAt:     r.GetUpdatedAt().Time,
		}
		if t, ok := tracked[dto.GithubRepoID]; ok {
			dto.IsTracked = true
			tid := t.ID
			dto.TrackedRepoID = &tid
			dto.LastScannedAt = t.LastScannedAt
			dto.LatestScanStatus = t.LatestScanStatus
			dto.IsInternetExposed = t.IsInternetExposed
		}
		dtos = append(dtos, dto)
	}

	c.JSON(http.StatusOK, browsePage{
		Repos:    dtos,
		Page:     page,
		PerPage:  perPage,
		NextPage: nextPage,
	})
}

type scanGitHubRepoRequest struct {
	GithubRepoID  int64  `json:"github_repo_id" binding:"required"`
	FullName      string `json:"full_name" binding:"required"`
	DefaultBranch string `json:"default_branch"`
}

// scanGitHubRepo persists a GitHub repo into our DB (if new) and enqueues a
// manual scan job when no scan is already pending or running for that repo.
func (h *OrgsHandler) scanGitHubRepo(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	org, ok := h.loadOrgForTenant(c, orgID)
	if !ok {
		return
	}

	var req scanGitHubRepoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	branch := req.DefaultBranch
	if branch == "" {
		branch = "main"
	}

	var repoID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO repositories (id, org_id, github_repo_id, full_name, default_branch, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (org_id, github_repo_id) DO UPDATE SET
			full_name = EXCLUDED.full_name,
			default_branch = EXCLUDED.default_branch
		RETURNING id`,
		uuid.New(), org.ID, req.GithubRepoID, req.FullName, branch,
	).Scan(&repoID)
	if err != nil {
		h.log.Error("upsert repository", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save repository"})
		return
	}

	if err := h.scheduler.EnqueueRepo(repoID, models.TriggerManual); err != nil {
		if respondScanEnqueueError(c, err, gin.H{"repo_id": repoID}) {
			return
		}
		h.log.Error("enqueue scan", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not enqueue scan"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"repo_id": repoID,
		"message": "scan enqueued",
	})
}

type scanBatchRequest struct {
	Repos []scanGitHubRepoRequest `json:"repos" binding:"required,min=1,dive"`
}

type scanBatchResponse struct {
	Enqueued     int           `json:"enqueued"`
	Failed       int           `json:"failed"`
	Blocked      int           `json:"blocked"`
	Skipped      int           `json:"skipped"`
	RepoIDs      []string      `json:"repo_ids"`
	BlockedRepos []blockedRepo `json:"blocked_repos"`
	SkippedRepos []blockedRepo `json:"skipped_repos"`
}

// scanGitHubReposBatch upserts each requested repo and enqueues a scan for it.
// Capped at maxBatchScan items per request to bound work.
func (h *OrgsHandler) scanGitHubReposBatch(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	org, ok := h.loadOrgForTenant(c, orgID)
	if !ok {
		return
	}

	var req scanBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Repos) > maxBatchScan {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "too many repos in batch (max " + strconv.Itoa(maxBatchScan) + ")",
		})
		return
	}

	resp := scanBatchResponse{
		RepoIDs:      make([]string, 0, len(req.Repos)),
		BlockedRepos: make([]blockedRepo, 0),
		SkippedRepos: make([]blockedRepo, 0),
	}
	for _, r := range req.Repos {
		repoID, err := h.upsertAndEnqueue(c.Request.Context(), org.ID, r)
		if err != nil {
			if errors.Is(err, repositoriesvc.ErrScanBlockedMissingInternetExposure) {
				resp.Blocked++
				resp.BlockedRepos = append(resp.BlockedRepos, blockedRepo{
					RepoID: r.FullName,
					Reason: "scan_blocked_missing_internet_exposure",
				})
				continue
			}
			if errors.Is(err, repositoriesvc.ErrScanAlreadyQueuedOrRunning) {
				resp.Skipped++
				resp.SkippedRepos = append(resp.SkippedRepos, blockedRepo{
					RepoID: r.FullName,
					Reason: "scan_already_queued_or_running",
				})
				continue
			}
			h.log.Warn("batch scan: upsert/enqueue failed",
				zap.String("full_name", r.FullName), zap.Error(err))
			resp.Failed++
			continue
		}
		resp.Enqueued++
		resp.RepoIDs = append(resp.RepoIDs, repoID.String())
	}

	c.JSON(http.StatusAccepted, resp)
}

// upsertAndEnqueue persists the repo (idempotent on org_id+github_repo_id) and
// enqueues a manual scan job. Returns the persisted repository ID.
func (h *OrgsHandler) upsertAndEnqueue(
	ctx context.Context, orgID uuid.UUID, r scanGitHubRepoRequest,
) (uuid.UUID, error) {
	branch := r.DefaultBranch
	if branch == "" {
		branch = "main"
	}

	var repoID uuid.UUID
	err := h.db.QueryRow(ctx, `
		INSERT INTO repositories (id, org_id, github_repo_id, full_name, default_branch, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (org_id, github_repo_id) DO UPDATE SET
			full_name = EXCLUDED.full_name,
			default_branch = EXCLUDED.default_branch
		RETURNING id`,
		uuid.New(), orgID, r.GithubRepoID, r.FullName, branch,
	).Scan(&repoID)
	if err != nil {
		return uuid.Nil, err
	}
	if err := h.scheduler.EnqueueRepo(repoID, models.TriggerManual); err != nil {
		return uuid.Nil, err
	}
	return repoID, nil
}

type syncResponse struct {
	TotalFromGitHub int `json:"total_from_github"`
	Imported        int `json:"imported"`
	Updated         int `json:"updated"`
}

// syncOrgRepos fetches the full repo list from GitHub and upserts every entry
// into our DB. It never enqueues scan jobs - use scan-batch for that. Runs
// synchronously; for huge orgs (1000+ repos) consider moving to a background
// job in the future.
func (h *OrgsHandler) syncOrgRepos(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	org, ok := h.loadOrgForTenant(c, orgID)
	if !ok {
		return
	}

	repos, err := h.github.ListOrgRepos(c.Request.Context(), claims.TenantID,
		*org.GithubAppInstallationID, org.GithubOrgLogin)
	if err != nil {
		if status, msg := classifyGitHubError(err); status > 0 {
			c.JSON(status, gin.H{"error": msg})
			return
		}
		h.log.Error("sync: list github repos", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not list repos from GitHub: " + err.Error()})
		return
	}

	resp := syncResponse{TotalFromGitHub: len(repos)}

	// Count how many of these GitHub IDs are already in our DB BEFORE upserting,
	// so we can report "imported" vs "updated" accurately.
	existedBefore := 0
	if len(repos) > 0 {
		ids := make([]int64, len(repos))
		for i, r := range repos {
			ids[i] = r.GetID()
		}
		_ = h.db.QueryRow(c.Request.Context(), `
			SELECT COUNT(*) FROM repositories
			WHERE org_id = $1 AND github_repo_id = ANY($2)`,
			org.ID, ids,
		).Scan(&existedBefore)
	}

	for _, r := range repos {
		branch := r.GetDefaultBranch()
		if branch == "" {
			branch = "main"
		}
		_, err := h.db.Exec(c.Request.Context(), `
			INSERT INTO repositories (id, org_id, github_repo_id, full_name, default_branch, created_at)
			VALUES ($1, $2, $3, $4, $5, NOW())
			ON CONFLICT (org_id, github_repo_id) DO UPDATE SET
				full_name = EXCLUDED.full_name,
				default_branch = EXCLUDED.default_branch`,
			uuid.New(), org.ID, r.GetID(), r.GetFullName(), branch,
		)
		if err != nil {
			h.log.Warn("sync: upsert repo failed",
				zap.String("full_name", r.GetFullName()), zap.Error(err))
			continue
		}
	}

	resp.Updated = existedBefore
	resp.Imported = len(repos) - existedBefore

	h.log.Info("org sync completed",
		zap.String("org_id", org.ID.String()),
		zap.Int("total", resp.TotalFromGitHub),
		zap.Int("imported", resp.Imported),
		zap.Int("updated", resp.Updated),
	)

	c.JSON(http.StatusOK, resp)
}

func (h *OrgsHandler) syncMemberships(c *gin.Context) {
	if !h.membershipEnabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "GitHub membership sync is disabled"})
		return
	}

	claims := middleware.ClaimsFrom(c)
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	org, ok := h.loadOrgForTenant(c, orgID)
	if !ok {
		return
	}

	result, err := h.membership.SyncOrg(c.Request.Context(), claims.TenantID, org.ID)
	if err != nil {
		if status, msg := classifyGitHubError(err); status > 0 {
			c.JSON(status, gin.H{"error": msg})
			return
		}
		h.log.Error("sync memberships", zap.String("org_id", org.ID.String()), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not sync memberships: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}
