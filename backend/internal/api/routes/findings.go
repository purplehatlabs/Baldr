package routes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/config"
	findingsvc "github.com/purplehatlabs/Baldr/internal/findings"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/i18n"
	"github.com/purplehatlabs/Baldr/internal/models"
	"github.com/purplehatlabs/Baldr/internal/queue"
	"go.uber.org/zap"
)

type FindingsHandler struct {
	db             *pgxpool.Pool
	log            *zap.Logger
	enqueuer       *queue.Enqueuer
	analysis       *findingsvc.Service
	prioritization *findingsvc.PrioritizationService
	triage         *findingsvc.TriageService
}

func NewFindingsHandler(db *pgxpool.Pool, enqueuer *queue.Enqueuer, cfg *config.Config, gh *githubclient.Client, log *zap.Logger) *FindingsHandler {
	return &FindingsHandler{
		db:             db,
		log:            log,
		enqueuer:       enqueuer,
		analysis:       findingsvc.NewService(db, cfg, gh, log),
		prioritization: findingsvc.NewPrioritizationService(db),
		triage:         findingsvc.NewTriageService(db),
	}
}

func (h *FindingsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/findings", authMW)
	g.GET("", h.list)
	g.GET("/top-risks", h.topRisks)
	g.POST("/manual", h.createManual)
	g.GET("/:id", h.get)
	g.PATCH("/:id", h.update)
	g.POST("/:id/triage/confirm", h.confirmTriage)
	g.POST("/:id/triage/dismiss", h.dismissTriage)
	g.POST("/:id/triage/reopen", h.reopenTriage)
	g.POST("/bulk/actions", h.bulkActions)
	g.POST("/:id/analyze", h.analyze)

	views := r.Group("/api/v1/views", authMW)
	views.GET("", h.listViews)
	views.POST("", h.createView)
	views.PUT("/:id", h.updateView)
	views.DELETE("/:id", h.deleteView)
}

type findingTeam struct {
	ID          uuid.UUID `json:"id"`
	Slug        string    `json:"slug"`
	DisplayName string    `json:"display_name"`
}

type findingOwner struct {
	UserID      *uuid.UUID `json:"user_id,omitempty"`
	Name        string     `json:"name"`
	Email       string     `json:"email,omitempty"`
	AvatarURL   string     `json:"avatar_url,omitempty"`
	GitHubLogin string     `json:"github_login,omitempty"`
	TeamSlug    string     `json:"team_slug,omitempty"`
	Source      string     `json:"source"`
}

type aiAnalysisSnapshot struct {
	AnalysisStatus        *models.AnalysisStatus        `json:"ai_analysis_status,omitempty"`
	CriticalityVerdict    *models.CriticalityVerdict    `json:"ai_criticality_verdict,omitempty"`
	ExploitabilityVerdict *models.ExploitabilityVerdict `json:"ai_exploitability_verdict,omitempty"`
	Confidence            *float64                      `json:"ai_confidence,omitempty"`
	Reasoning             *string                       `json:"ai_reasoning,omitempty"`
	ExploitationPath      *string                       `json:"ai_exploitation_path,omitempty"`
	RemediationPath       *string                       `json:"ai_remediation_path,omitempty"`
	ReasoningDisplay      *string                       `json:"ai_reasoning_display,omitempty"`
	ExploitationDisplay   *string                       `json:"ai_exploitation_path_display,omitempty"`
	RemediationDisplay    *string                       `json:"ai_remediation_path_display,omitempty"`
	AnalyzedAt            *time.Time                    `json:"ai_analyzed_at,omitempty"`
	AnalysisError         *string                       `json:"ai_analysis_error,omitempty"`
	VulnerableCodePaths   []string                      `json:"ai_vulnerable_code_paths,omitempty"`
	HasContextualAnalysis *bool                         `json:"has_contextual_analysis,omitempty"`
}

type findingRow struct {
	models.Finding
	RepoFullName         string         `json:"repo_full_name"`
	ManifestPath         string         `json:"manifest_path"`
	Evidence             map[string]any `json:"evidence,omitempty"`
	ReachabilityEvidence map[string]any `json:"reachability_evidence,omitempty"`
	RiskFactors          []any          `json:"risk_factors,omitempty"`
	Teams                []findingTeam  `json:"teams"`
	Owners               []findingOwner `json:"owners"`
	aiAnalysisSnapshot
}

const findingsTenantBaseFrom = `
		FROM findings f
		LEFT JOIN manifests m ON m.id = f.manifest_id
		LEFT JOIN repositories r ON r.id = m.repo_id
		LEFT JOIN organizations o ON o.id = r.org_id
		WHERE (f.tenant_id = $1 OR o.tenant_id = $1)`

const findingSelectColumns = `
		f.id, f.tenant_id, f.scan_job_id, f.manifest_id, f.osv_id, f.package_name,
		f.package_version, f.fixed_version, f.severity, f.cvss_score,
		f.summary, f.details, f.status, f.first_seen_at, f.last_seen_at,
		f.reachability_status, f.reachability_confidence, f.reachability_evidence_json, f.reachability_analyzed_at,
		f.risk_score, f.risk_tier, f.risk_factors_json, f.risk_scored_at, f.sla_due_at, f.is_sla_breached,
		f.triage_status, f.triage_decided_at, f.triage_decided_by_user_id, f.triage_decision_source,
		f.finding_type, f.source_engine, f.external_source, f.external_reference,
		f.reported_at, f.created_by_user_id, f.business_impact, f.evidence_json,
		COALESCE(r.full_name, ''), COALESCE(m.path, '')`

func scanFindingRow(rows interface{ Scan(...any) error }, dest *findingRow) error {
	var evidenceRaw, factorsRaw, manualEvidenceRaw []byte
	if err := rows.Scan(
		&dest.ID, &dest.TenantID, &dest.ScanJobID, &dest.ManifestID, &dest.OSVID, &dest.PackageName,
		&dest.PackageVersion, &dest.FixedVersion, &dest.Severity, &dest.CVSSScore,
		&dest.Summary, &dest.Details, &dest.Status, &dest.FirstSeenAt, &dest.LastSeenAt,
		&dest.ReachabilityStatus, &dest.ReachabilityConfidence, &evidenceRaw, &dest.ReachabilityAnalyzedAt,
		&dest.RiskScore, &dest.RiskTier, &factorsRaw, &dest.RiskScoredAt, &dest.SLADueAt, &dest.IsSLABreached,
		&dest.TriageStatus, &dest.TriageDecidedAt, &dest.TriageDecidedByUserID, &dest.TriageDecisionSource,
		&dest.FindingType, &dest.SourceEngine, &dest.ExternalSource, &dest.ExternalReference,
		&dest.ReportedAt, &dest.CreatedByUserID, &dest.BusinessImpact, &manualEvidenceRaw,
		&dest.RepoFullName, &dest.ManifestPath,
	); err != nil {
		return err
	}
	dest.ReachabilityEvidence = decodeJSONMap(evidenceRaw)
	dest.RiskFactors = decodeJSONArray(factorsRaw)
	dest.Evidence = decodeJSONMap(manualEvidenceRaw)
	return nil
}

func decodeJSONMap(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func decodeJSONArray(raw []byte) []any {
	if len(raw) == 0 {
		return nil
	}
	out := []any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (h *FindingsHandler) resolveUserLocale(ctx context.Context, c *gin.Context) string {
	claims := middleware.ClaimsFrom(c)
	if claims == nil {
		return i18n.DefaultLocale
	}

	var language string
	err := h.db.QueryRow(ctx, `
		SELECT COALESCE(NULLIF(language, ''), 'en')
		FROM users
		WHERE id = $1 AND tenant_id = $2`, claims.UserID, claims.TenantID,
	).Scan(&language)
	if err != nil {
		return i18n.DefaultLocale
	}
	return i18n.ParseLocale(language)
}

func applyFindingListFilters(baseQuery string, args []any, c *gin.Context) (string, []any, int) {
	i := len(args) + 1

	if severity := c.Query("severity"); severity != "" {
		baseQuery += ` AND f.severity = $` + itoa(i)
		args = append(args, severity)
		i++
	}
	if status := c.Query("status"); status != "" {
		baseQuery += ` AND f.status = $` + itoa(i)
		args = append(args, status)
		i++
	}
	if teamID := c.Query("team_id"); teamID != "" {
		baseQuery += ` AND EXISTS (
			SELECT 1 FROM finding_teams ft WHERE ft.finding_id = f.id AND ft.team_id = $` + itoa(i) + `)`
		args = append(args, teamID)
		i++
	}
	if repoID := c.Query("repo_id"); repoID != "" {
		baseQuery += ` AND r.id = $` + itoa(i)
		args = append(args, repoID)
		i++
	}
	if reachability := c.Query("reachability"); reachability != "" {
		baseQuery += ` AND f.reachability_status = $` + itoa(i)
		args = append(args, reachability)
		i++
	}
	if riskTier := c.Query("risk_tier"); riskTier != "" {
		baseQuery += ` AND f.risk_tier = $` + itoa(i)
		args = append(args, riskTier)
		i++
	}
	if c.Query("sla_breached") == "true" {
		baseQuery += ` AND f.is_sla_breached = TRUE`
	}
	if excludeExceptions := c.DefaultQuery("exclude_exceptions", ""); excludeExceptions == "true" {
		baseQuery += ` AND NOT EXISTS (
			SELECT 1 FROM finding_exceptions fe
			WHERE fe.finding_id = f.id AND fe.tenant_id = COALESCE(f.tenant_id, o.tenant_id)
			  AND (fe.expires_at IS NULL OR fe.expires_at > NOW())
		)`
	}
	if sourceEngine := c.Query("source_engine"); sourceEngine != "" {
		baseQuery += ` AND f.source_engine = $` + itoa(i)
		args = append(args, sourceEngine)
		i++
	}
	if c.DefaultQuery("triage_queue", "") == "pending" {
		baseQuery += ` AND f.triage_status IN ('new', 'needs_review')`
	} else if triageStatus := c.Query("triage_status"); triageStatus != "" {
		parts := strings.Split(triageStatus, ",")
		allowed := make([]string, 0, len(parts))
		for _, part := range parts {
			value := strings.TrimSpace(part)
			switch value {
			case string(models.TriageNew), string(models.TriageNeedsReview),
				string(models.TriageConfirmed), string(models.TriageDismissed):
				allowed = append(allowed, value)
			}
		}
		if len(allowed) > 0 {
			baseQuery += ` AND f.triage_status = ANY($` + itoa(i) + `)`
			args = append(args, allowed)
			i++
		}
	}
	if searchQuery := strings.TrimSpace(c.Query("q")); searchQuery != "" {
		baseQuery += ` AND (
			f.package_name ILIKE $` + itoa(i) + `
			OR f.osv_id ILIKE $` + itoa(i) + `
			OR f.summary ILIKE $` + itoa(i) + `
			OR f.details ILIKE $` + itoa(i) + `
			OR r.full_name ILIKE $` + itoa(i) + `
		)`
		args = append(args, "%"+searchQuery+"%")
		i++
	}

	return baseQuery, args, i
}

func (h *FindingsHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	page := 1
	if raw := c.DefaultQuery("page", "1"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid page"})
			return
		}
		page = value
	}

	pageSize := 50
	if raw := c.DefaultQuery("page_size", "50"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid page_size"})
			return
		}
		pageSize = value
	}
	offset := (page - 1) * pageSize

	sortBy := c.DefaultQuery("sort", "last_seen_at")
	sortField := map[string]string{
		"last_seen_at":  "f.last_seen_at",
		"first_seen_at": "f.first_seen_at",
		"severity":      "f.severity",
		"status":        "f.status",
		"cvss_score":    "f.cvss_score",
		"package_name":  "f.package_name",
		"risk_score":    "f.risk_score",
	}[sortBy]
	if sortField == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sort"})
		return
	}

	order := strings.ToUpper(c.DefaultQuery("order", "desc"))
	if order != "ASC" && order != "DESC" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid order"})
		return
	}

	baseQuery := findingsTenantBaseFrom

	args := []any{claims.TenantID}
	baseQuery, args, i := applyFindingListFilters(baseQuery, args, c)

	var total int
	if err := h.db.QueryRow(c.Request.Context(), `SELECT COUNT(*) `+baseQuery, args...).Scan(&total); err != nil {
		h.log.Error("count findings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	query := `SELECT ` + findingSelectColumns + baseQuery + ` ORDER BY ` + sortField + ` ` + order + ` LIMIT $` + itoa(i) + ` OFFSET $` + itoa(i+1)
	args = append(args, pageSize, offset)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.log.Error("list findings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var findings []findingRow
	findingIDs := []uuid.UUID{}
	for rows.Next() {
		var f findingRow
		if err := scanFindingRow(rows, &f); err != nil {
			continue
		}
		f.Teams = []findingTeam{}
		f.Owners = []findingOwner{}
		findings = append(findings, f)
		findingIDs = append(findingIDs, f.ID)
	}

	if err := h.attachTeams(c.Request.Context(), findings, findingIDs); err != nil {
		h.log.Warn("attach teams", zap.Error(err))
	}
	if err := h.attachOwners(c.Request.Context(), findings, findingIDs); err != nil {
		h.log.Warn("attach owners", zap.Error(err))
	}
	if err := h.attachLatestAnalyses(c.Request.Context(), h.resolveUserLocale(c.Request.Context(), c), findings, findingIDs); err != nil {
		h.log.Warn("attach analyses", zap.Error(err))
	}

	if findings == nil {
		findings = []findingRow{}
	}
	totalPages := 0
	if pageSize > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	c.JSON(http.StatusOK, gin.H{
		"items":       findings,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

func (h *FindingsHandler) attachLatestAnalyses(ctx context.Context, locale string, findings []findingRow, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	rows, err := h.db.Query(ctx, `
		SELECT DISTINCT ON (fa.finding_id)
			fa.finding_id, fa.analysis_status, fa.criticality_verdict,
			fa.exploitability_verdict, fa.confidence, fa.reasoning,
			fa.exploitation_path, fa.remediation_path,
			fa.reasoning_pt_br, fa.exploitation_path_pt_br, fa.remediation_path_pt_br,
			fa.completed_at, fa.error_msg,
			fa.vulnerable_code_paths_json
		FROM finding_analyses fa
		WHERE fa.finding_id = ANY($1)
		ORDER BY fa.finding_id, fa.created_at DESC`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()

	byID := map[uuid.UUID]int{}
	for i := range findings {
		byID[findings[i].ID] = i
	}

	for rows.Next() {
		var fid uuid.UUID
		var status models.AnalysisStatus
		var criticality, exploitability *string
		var confidence *float64
		var reasoning, exploitation, remediation *string
		var reasoningPtBR, exploitationPtBR, remediationPtBR *string
		var completedAt *time.Time
		var errMsg *string
		var vulnPathsRaw []byte

		if err := rows.Scan(
			&fid, &status, &criticality, &exploitability, &confidence,
			&reasoning, &exploitation, &remediation,
			&reasoningPtBR, &exploitationPtBR, &remediationPtBR,
			&completedAt, &errMsg, &vulnPathsRaw,
		); err != nil {
			continue
		}

		idx, ok := byID[fid]
		if !ok {
			continue
		}
		findings[idx].AnalysisStatus = &status
		if criticality != nil {
			v := models.CriticalityVerdict(*criticality)
			findings[idx].CriticalityVerdict = &v
		}
		if exploitability != nil {
			v := models.ExploitabilityVerdict(*exploitability)
			findings[idx].ExploitabilityVerdict = &v
		}
		findings[idx].Confidence = confidence
		findings[idx].Reasoning = reasoning
		findings[idx].ExploitationPath = exploitation
		findings[idx].RemediationPath = remediation
		findings[idx].ReasoningDisplay = i18n.ResolveDisplayText(locale, reasoning, reasoningPtBR)
		findings[idx].ExploitationDisplay = i18n.ResolveDisplayText(locale, exploitation, exploitationPtBR)
		findings[idx].RemediationDisplay = i18n.ResolveDisplayText(locale, remediation, remediationPtBR)
		findings[idx].AnalyzedAt = completedAt
		findings[idx].AnalysisError = errMsg
		if status == models.AnalysisCompleted {
			hasContextual := true
			findings[idx].HasContextualAnalysis = &hasContextual
		}
		if len(vulnPathsRaw) > 0 {
			var paths []string
			if err := json.Unmarshal(vulnPathsRaw, &paths); err == nil {
				findings[idx].VulnerableCodePaths = paths
			}
		}
	}
	return nil
}

func (h *FindingsHandler) attachTeams(ctx context.Context, findings []findingRow, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	rows, err := h.db.Query(ctx, `
		SELECT ft.finding_id, t.id, t.github_team_slug, t.display_name
		FROM finding_teams ft
		JOIN teams t ON t.id = ft.team_id
		WHERE ft.finding_id = ANY($1)
		ORDER BY t.display_name`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()

	byID := map[uuid.UUID]int{}
	for i := range findings {
		byID[findings[i].ID] = i
	}

	for rows.Next() {
		var fid uuid.UUID
		var team findingTeam
		if err := rows.Scan(&fid, &team.ID, &team.Slug, &team.DisplayName); err != nil {
			continue
		}
		if idx, ok := byID[fid]; ok {
			findings[idx].Teams = append(findings[idx].Teams, team)
		}
	}
	return nil
}

func (h *FindingsHandler) attachOwners(ctx context.Context, findings []findingRow, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	rows, err := h.db.Query(ctx, `
		SELECT DISTINCT ON (ft.finding_id, COALESCE(u.id::text, om.id::text))
			ft.finding_id,
			u.id,
			COALESCE(NULLIF(u.name, ''), NULLIF(om.name, ''), om.github_login) AS name,
			COALESCE(u.email, '') AS email,
			COALESCE(NULLIF(u.avatar_url, ''), om.avatar_url) AS avatar_url,
			om.github_login,
			t.github_team_slug,
			CASE WHEN u.id IS NOT NULL THEN 'linked_user' ELSE 'org_member' END AS source
		FROM finding_teams ft
		JOIN teams t ON t.id = ft.team_id
		JOIN team_members tm ON tm.team_id = t.id
		JOIN org_members om ON om.id = tm.org_member_id AND om.is_active = TRUE
		LEFT JOIN users u ON u.id = om.user_id
		WHERE ft.finding_id = ANY($1)
		ORDER BY ft.finding_id, COALESCE(u.id::text, om.id::text), om.github_login`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()

	byID := map[uuid.UUID]int{}
	for i := range findings {
		byID[findings[i].ID] = i
	}

	for rows.Next() {
		var fid uuid.UUID
		var owner findingOwner
		var userID *uuid.UUID
		if err := rows.Scan(
			&fid, &userID, &owner.Name, &owner.Email, &owner.AvatarURL,
			&owner.GitHubLogin, &owner.TeamSlug, &owner.Source,
		); err != nil {
			continue
		}
		owner.UserID = userID
		if idx, ok := byID[fid]; ok {
			findings[idx].Owners = append(findings[idx].Owners, owner)
		}
	}

	// Fallback: teams without synced members still show team slug as pseudo-owner
	rows2, err := h.db.Query(ctx, `
		SELECT ft.finding_id, t.github_team_slug, t.display_name
		FROM finding_teams ft
		JOIN teams t ON t.id = ft.team_id
		WHERE ft.finding_id = ANY($1)
		  AND NOT EXISTS (
			SELECT 1 FROM team_members tm
			JOIN org_members om ON om.id = tm.org_member_id AND om.is_active = TRUE
			WHERE tm.team_id = t.id
		  )`, ids)
	if err != nil {
		return err
	}
	defer rows2.Close()

	for rows2.Next() {
		var fid uuid.UUID
		var slug, displayName string
		if err := rows2.Scan(&fid, &slug, &displayName); err != nil {
			continue
		}
		idx, ok := byID[fid]
		if !ok {
			continue
		}
		findings[idx].Owners = append(findings[idx].Owners, findingOwner{
			Name:     displayName,
			TeamSlug: slug,
			Source:   "team_fallback",
		})
	}

	return nil
}

func (h *FindingsHandler) topRisks(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	limit := 10
	if raw := c.DefaultQuery("limit", "10"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 50 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = value
	}

	baseQuery := findingsTenantBaseFrom + `
		  AND f.status = 'open'
		  AND f.triage_status = 'confirmed'
		  AND NOT EXISTS (
			SELECT 1 FROM finding_exceptions fe
			WHERE fe.finding_id = f.id AND fe.tenant_id = COALESCE(f.tenant_id, o.tenant_id)
			  AND (fe.expires_at IS NULL OR fe.expires_at > NOW())
		)`

	args := []any{claims.TenantID}
	baseQuery, args, i := applyFindingListFilters(baseQuery, args, c)

	query := `SELECT ` + findingSelectColumns + baseQuery + ` ORDER BY f.risk_score DESC, f.last_seen_at DESC LIMIT $` + itoa(i)
	args = append(args, limit)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.log.Error("top risks", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	findings := make([]findingRow, 0, limit)
	findingIDs := []uuid.UUID{}
	for rows.Next() {
		var f findingRow
		if err := scanFindingRow(rows, &f); err != nil {
			continue
		}
		f.Teams = []findingTeam{}
		f.Owners = []findingOwner{}
		findings = append(findings, f)
		findingIDs = append(findingIDs, f.ID)
	}

	if err := h.attachTeams(c.Request.Context(), findings, findingIDs); err != nil {
		h.log.Warn("attach teams", zap.Error(err))
	}
	if err := h.attachOwners(c.Request.Context(), findings, findingIDs); err != nil {
		h.log.Warn("attach owners", zap.Error(err))
	}
	if err := h.attachLatestAnalyses(c.Request.Context(), h.resolveUserLocale(c.Request.Context(), c), findings, findingIDs); err != nil {
		h.log.Warn("attach analyses", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{"items": findings, "total": len(findings)})
}

func (h *FindingsHandler) createManual(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	if claims.Role != string(models.RoleAdmin) && claims.Role != string(models.RoleOwner) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin or owner role required"})
		return
	}

	var req models.CreateManualFindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Summary = strings.TrimSpace(req.Summary)
	req.ExternalReference = strings.TrimSpace(req.ExternalReference)
	if req.Summary == "" || req.ExternalReference == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "summary and external_reference are required"})
		return
	}

	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid evidence"})
		return
	}
	if req.Evidence == nil {
		evidenceJSON = []byte("{}")
	}

	now := time.Now().UTC()
	reportedAt := now
	if req.ReportedAt != nil {
		reportedAt = req.ReportedAt.UTC()
	}

	findingID := uuid.New()
	source := models.TriageDecisionManual
	packageName := strings.TrimSpace(req.PackageName)
	packageVersion := strings.TrimSpace(req.PackageVersion)
	details := strings.TrimSpace(req.Details)
	if details == "" {
		details = req.Summary
	}

	tx, err := h.db.Begin(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer tx.Rollback(c.Request.Context())

	err = tx.QueryRow(c.Request.Context(), `
		INSERT INTO findings (
			id, tenant_id, scan_job_id, manifest_id, osv_id, package_name, package_version,
			severity, cvss_score, summary, details, status,
			finding_type, source_engine, external_source, external_reference,
			reported_at, created_by_user_id, business_impact, evidence_json,
			triage_status, triage_decided_at, triage_decided_by_user_id, triage_decision_source,
			first_seen_at, last_seen_at
		) VALUES (
			$1, $2, NULL, NULL, $3, $4, $5,
			$6, $7, $8, $9, 'open',
			'vulnerability', 'manual', $10, $11,
			$12, $13, $14, $15,
			'confirmed', $16, $13, $17,
			$16, $16
		)
		RETURNING id`,
		findingID, claims.TenantID, req.ExternalReference, packageName, packageVersion,
		req.Severity, req.CVSSScore, req.Summary, details,
		strings.TrimSpace(req.ExternalSource), req.ExternalReference,
		reportedAt, claims.UserID, strings.TrimSpace(req.BusinessImpact), evidenceJSON,
		now, source,
	).Scan(&findingID)
	if err != nil {
		h.log.Error("create manual finding", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if req.SLADueAt != nil {
		slaDue := req.SLADueAt.UTC()
		if _, err := tx.Exec(c.Request.Context(), `
			UPDATE findings SET sla_due_at = $1 WHERE id = $2 AND tenant_id = $3`,
			slaDue, findingID, claims.TenantID,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}

	if err := h.insertFindingAuditLog(c.Request.Context(), tx, claims.TenantID, claims.UserID, findingID, "manual_create", "", "open", map[string]any{
		"source_engine":      "manual",
		"external_reference": req.ExternalReference,
		"external_source":    strings.TrimSpace(req.ExternalSource),
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := h.prioritization.RecalculateRiskScore(c.Request.Context(), findingID, claims.TenantID); err != nil {
		h.log.Warn("recalculate risk score after manual create", zap.Error(err))
	}

	c.JSON(http.StatusCreated, gin.H{"id": findingID})
}

func (h *FindingsHandler) get(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	findingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var f findingRow
	row := h.db.QueryRow(c.Request.Context(), `
		SELECT `+findingSelectColumns+findingsTenantBaseFrom+`
		  AND f.id = $2`,
		claims.TenantID, findingID,
	)
	if err := scanFindingRow(row, &f); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	f.Teams = []findingTeam{}
	f.Owners = []findingOwner{}
	single := []findingRow{f}
	if err := h.attachTeams(c.Request.Context(), single, []uuid.UUID{f.ID}); err != nil {
		h.log.Warn("attach teams", zap.Error(err))
	}
	if err := h.attachOwners(c.Request.Context(), single, []uuid.UUID{f.ID}); err != nil {
		h.log.Warn("attach owners", zap.Error(err))
	}
	if err := h.attachLatestAnalyses(c.Request.Context(), h.resolveUserLocale(c.Request.Context(), c), single, []uuid.UUID{f.ID}); err != nil {
		h.log.Warn("attach analyses", zap.Error(err))
	}
	f = single[0]

	c.JSON(http.StatusOK, f)
}

type updateFindingRequest struct {
	Status models.FindingStatus `json:"status" binding:"required,oneof=open suppressed fixed"`
}

func (h *FindingsHandler) update(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	findingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var req updateFindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx, err := h.db.Begin(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer tx.Rollback(c.Request.Context())

	var previousStatus string
	err = tx.QueryRow(c.Request.Context(), `
		SELECT f.status
		FROM findings f
		WHERE f.id = $1 AND f.tenant_id = $2`,
		findingID, claims.TenantID,
	).Scan(&previousStatus)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	_, err = tx.Exec(c.Request.Context(), `
		UPDATE findings SET status = $1
		WHERE id = $2 AND tenant_id = $3`,
		req.Status, findingID, claims.TenantID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := h.insertFindingAuditLog(c.Request.Context(), tx, claims.TenantID, claims.UserID, findingID, "status_update", previousStatus, string(req.Status), map[string]any{
		"source": "patch",
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := h.prioritization.RecalculateRiskScore(c.Request.Context(), findingID, claims.TenantID); err != nil {
		h.log.Warn("recalculate risk score after status update", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *FindingsHandler) confirmTriage(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	findingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := h.triage.Confirm(c.Request.Context(), findingID, claims.TenantID, claims.UserID); err != nil {
		h.respondTriageError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "triage_status": models.TriageConfirmed})
}

func (h *FindingsHandler) dismissTriage(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	findingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := h.triage.Dismiss(c.Request.Context(), findingID, claims.TenantID, claims.UserID); err != nil {
		h.respondTriageError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"triage_status": models.TriageDismissed,
		"status":        models.FindingSuppressed,
	})
}

func (h *FindingsHandler) reopenTriage(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	findingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := h.triage.Reopen(c.Request.Context(), findingID, claims.TenantID, claims.UserID, claims.Role); err != nil {
		h.respondTriageError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"triage_status": models.TriageNeedsReview,
		"status":        models.FindingOpen,
	})
}

func (h *FindingsHandler) respondTriageError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, findingsvc.ErrInvalidTriageTransition):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, findingsvc.ErrTriageAdminRequired):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, findingsvc.ErrFindingNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	default:
		h.log.Error("triage action", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
	}
}

type bulkActionRequest struct {
	Action         string      `json:"action" binding:"required,oneof=assign suppress reopen mark_fixed"`
	FindingIDs     []uuid.UUID `json:"finding_ids" binding:"required,min=1"`
	AssignedUserID *uuid.UUID  `json:"assigned_user_id"`
}

func (h *FindingsHandler) bulkActions(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req bulkActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Action == "assign" && req.AssignedUserID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "assigned_user_id is required for assign action"})
		return
	}

	tx, err := h.db.Begin(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer tx.Rollback(c.Request.Context())

	rows, err := tx.Query(c.Request.Context(), `
		SELECT f.id, f.status
		FROM findings f
		WHERE f.tenant_id = $1
		  AND f.id = ANY($2)`,
		claims.TenantID, req.FindingIDs,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	found := make([]struct {
		ID     uuid.UUID
		Status string
	}, 0, len(req.FindingIDs))
	for rows.Next() {
		var row struct {
			ID     uuid.UUID
			Status string
		}
		if err := rows.Scan(&row.ID, &row.Status); err != nil {
			continue
		}
		found = append(found, row)
	}

	if len(found) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no findings found"})
		return
	}

	var targetStatus *string
	switch req.Action {
	case "suppress":
		value := string(models.FindingSuppressed)
		targetStatus = &value
	case "reopen":
		value := string(models.FindingOpen)
		targetStatus = &value
	case "mark_fixed":
		value := string(models.FindingFixed)
		targetStatus = &value
	}

	if targetStatus != nil {
		if _, err := tx.Exec(c.Request.Context(), `
			UPDATE findings
			SET status = $1
			WHERE id = ANY($2)
			  AND tenant_id = $3`,
			*targetStatus, req.FindingIDs, claims.TenantID,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}

	for _, item := range found {
		metadata := map[string]any{
			"source": "bulk",
			"action": req.Action,
		}
		newStatus := item.Status
		if targetStatus != nil {
			newStatus = *targetStatus
		}
		if req.Action == "assign" && req.AssignedUserID != nil {
			metadata["assigned_user_id"] = req.AssignedUserID.String()
		}
		if err := h.insertFindingAuditLog(
			c.Request.Context(),
			tx,
			claims.TenantID,
			claims.UserID,
			item.ID,
			req.Action,
			item.Status,
			newStatus,
			metadata,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	for _, item := range found {
		if err := h.prioritization.RecalculateRiskScore(c.Request.Context(), item.ID, claims.TenantID); err != nil {
			h.log.Warn("recalculate risk score after bulk action", zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"action":        req.Action,
		"matched_count": len(found),
	})
}

func (h *FindingsHandler) analyze(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	findingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var scanJobID *uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT f.scan_job_id
		FROM findings f
		WHERE f.id = $1 AND f.tenant_id = $2`,
		findingID, claims.TenantID,
	).Scan(&scanJobID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if scanJobID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "analysis not available for manual findings"})
		return
	}

	analysisID, created, err := h.analysis.EnqueueAnalysis(
		c.Request.Context(),
		findingID,
		claims.TenantID,
		scanJobID,
		models.AnalysisTriggerManual,
		true,
	)
	if err != nil {
		h.log.Error("enqueue analysis", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not enqueue analysis"})
		return
	}

	if created {
		if err := h.enqueuer.EnqueueFindingAnalysis(analysisID, findingID, claims.TenantID); err != nil {
			h.log.Error("enqueue analysis task", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "queue unavailable"})
			return
		}
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message":     "analysis enqueued",
		"finding_id":  findingID,
		"analysis_id": analysisID,
	})
}

type savedViewResponse struct {
	ID        uuid.UUID      `json:"id"`
	Name      string         `json:"name"`
	Filters   map[string]any `json:"filters"`
	Sort      string         `json:"sort"`
	Order     string         `json:"order"`
	PageSize  int            `json:"page_size"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func (h *FindingsHandler) listViews(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, name, filters, sort, "order", page_size, created_at, updated_at
		FROM saved_views
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY name`,
		claims.TenantID, claims.UserID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	views := make([]savedViewResponse, 0)
	for rows.Next() {
		var (
			view savedViewResponse
			raw  []byte
		)
		if err := rows.Scan(&view.ID, &view.Name, &raw, &view.Sort, &view.Order, &view.PageSize, &view.CreatedAt, &view.UpdatedAt); err != nil {
			continue
		}
		view.Filters = map[string]any{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &view.Filters)
		}
		views = append(views, view)
	}

	c.JSON(http.StatusOK, views)
}

type upsertViewRequest struct {
	Name     string         `json:"name" binding:"required"`
	Filters  map[string]any `json:"filters"`
	Sort     string         `json:"sort"`
	Order    string         `json:"order"`
	PageSize *int           `json:"page_size"`
}

func (h *FindingsHandler) createView(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req upsertViewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sort, order, pageSize, filtersJSON, err := normalizeViewPayload(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var id uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO saved_views (tenant_id, user_id, name, filters, sort, "order", page_size, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING id`,
		claims.TenantID, claims.UserID, req.Name, filtersJSON, sort, order, pageSize,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *FindingsHandler) updateView(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	viewID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var req upsertViewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sort, order, pageSize, filtersJSON, err := normalizeViewPayload(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		UPDATE saved_views
		SET name = $1, filters = $2, sort = $3, "order" = $4, page_size = $5, updated_at = NOW()
		WHERE id = $6 AND tenant_id = $7 AND user_id = $8`,
		req.Name, filtersJSON, sort, order, pageSize, viewID, claims.TenantID, claims.UserID,
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

func (h *FindingsHandler) deleteView(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	viewID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM saved_views
		WHERE id = $1 AND tenant_id = $2 AND user_id = $3`,
		viewID, claims.TenantID, claims.UserID,
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

func normalizeViewPayload(req upsertViewRequest) (string, string, int, []byte, error) {
	sort := strings.TrimSpace(req.Sort)
	if sort == "" {
		sort = "last_seen_at"
	}
	validSort := map[string]bool{
		"last_seen_at":  true,
		"first_seen_at": true,
		"severity":      true,
		"status":        true,
		"cvss_score":    true,
		"package_name":  true,
	}
	if !validSort[sort] {
		return "", "", 0, nil, fmt.Errorf("invalid sort")
	}

	order := strings.ToLower(strings.TrimSpace(req.Order))
	if order == "" {
		order = "desc"
	}
	if order != "asc" && order != "desc" {
		return "", "", 0, nil, fmt.Errorf("invalid order")
	}

	pageSize := 50
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}
	if pageSize < 1 || pageSize > 200 {
		return "", "", 0, nil, fmt.Errorf("invalid page_size")
	}

	if req.Filters == nil {
		req.Filters = map[string]any{}
	}
	filtersJSON, err := json.Marshal(req.Filters)
	if err != nil {
		return "", "", 0, nil, fmt.Errorf("invalid filters")
	}

	return sort, order, pageSize, filtersJSON, nil
}

func (h *FindingsHandler) insertFindingAuditLog(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	actorUserID uuid.UUID,
	findingID uuid.UUID,
	action string,
	previousStatus string,
	newStatus string,
	metadata map[string]any,
) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO finding_audit_logs
			(tenant_id, finding_id, action, previous_status, new_status, actor_user_id, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		tenantID, findingID, action, previousStatus, newStatus, actorUserID, payload,
	)
	return err
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
