package routes

import (
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
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type SupplyChainSignalsHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewSupplyChainSignalsHandler(db *pgxpool.Pool, log *zap.Logger) *SupplyChainSignalsHandler {
	return &SupplyChainSignalsHandler{db: db, log: log}
}

func (h *SupplyChainSignalsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/supply-chain-signals", authMW)
	g.GET("", h.list)
	g.GET("/summary", h.summary)
	g.GET("/:id", h.get)
}

type supplyChainSignalListItem struct {
	ID               uuid.UUID                      `json:"id"`
	RepoID           *uuid.UUID                     `json:"repo_id,omitempty"`
	SignalType       models.SupplyChainSignalType   `json:"signal_type"`
	Status           models.SupplyChainSignalStatus `json:"status"`
	Severity         models.Severity                `json:"severity"`
	PackageEcosystem string                         `json:"package_ecosystem"`
	PackageName      string                         `json:"package_name"`
	PackageVersion   string                         `json:"package_version"`
	SourceEngine     string                         `json:"source_engine"`
	SignalKey        string                         `json:"signal_key"`
	SignalHash       string                         `json:"signal_hash"`
	Confidence       *float64                       `json:"confidence,omitempty"`
	Reasoning        string                         `json:"reasoning"`
	FirstSeenAt      time.Time                      `json:"first_seen_at"`
	LastSeenAt       time.Time                      `json:"last_seen_at"`
	ResolvedAt       *time.Time                     `json:"resolved_at,omitempty"`
	CreatedAt        time.Time                      `json:"created_at"`
	UpdatedAt        time.Time                      `json:"updated_at"`
	RepoFullName     string                         `json:"repo_full_name"`
}

type supplyChainSignalsListResponse struct {
	Items   []supplyChainSignalListItem `json:"items"`
	Page    int                         `json:"page"`
	PerPage int                         `json:"per_page"`
	Total   int                         `json:"total"`
}

type supplyChainSignalsSummaryResponse struct {
	Total        int            `json:"total"`
	ByStatus     map[string]any `json:"by_status"`
	BySeverity   map[string]any `json:"by_severity"`
	BySignalType map[string]any `json:"by_signal_type"`
	ByEngine     map[string]any `json:"by_engine"`
}

type supplyChainSignalDetailResponse struct {
	supplyChainSignalListItem
	Evidence map[string]any `json:"evidence"`
	Metadata map[string]any `json:"metadata"`
}

func (h *SupplyChainSignalsHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	page, perPage, err := parsePageParams(c, 50, 200)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	offset := (page - 1) * perPage

	var repoID *uuid.UUID
	if repoIDStr := strings.TrimSpace(c.Query("repo_id")); repoIDStr != "" {
		parsedID, parseErr := uuid.Parse(repoIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_id"})
			return
		}
		repoID = &parsedID
	}

	engine := strings.TrimSpace(c.Query("engine"))
	if engine != "" && !isValidSupplyChainSignalEngine(engine) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid engine"})
		return
	}

	status := strings.TrimSpace(c.Query("status"))
	if status != "" && !isValidSupplyChainSignalStatus(status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}

	signalType := strings.TrimSpace(c.Query("signal_type"))
	if signalType != "" && !isValidSupplyChainSignalType(signalType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid signal_type"})
		return
	}

	severity := strings.TrimSpace(c.Query("severity"))
	if severity != "" && !isValidSupplyChainSignalSeverity(severity) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
		return
	}

	args := []any{claims.TenantID}
	filter := `
		FROM supply_chain_signals s
		LEFT JOIN repositories r ON r.id = s.repo_id
		WHERE s.tenant_id = $1`

	if repoID != nil {
		args = append(args, *repoID)
		filter += fmt.Sprintf(` AND s.repo_id = $%d`, len(args))
	}
	if engine != "" {
		args = append(args, engine)
		filter += fmt.Sprintf(` AND s.source_engine = $%d`, len(args))
	}
	if status != "" {
		args = append(args, status)
		filter += fmt.Sprintf(` AND s.status = $%d`, len(args))
	}
	if signalType != "" {
		args = append(args, signalType)
		filter += fmt.Sprintf(` AND s.signal_type = $%d`, len(args))
	}
	if severity != "" {
		args = append(args, severity)
		filter += fmt.Sprintf(` AND s.severity = $%d`, len(args))
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		args = append(args, "%"+q+"%")
		filter += fmt.Sprintf(` AND (
			s.package_name ILIKE $%d
			OR s.package_version ILIKE $%d
			OR s.package_ecosystem ILIKE $%d
			OR s.reasoning ILIKE $%d
			OR s.signal_key ILIKE $%d
			OR s.signal_hash ILIKE $%d
			OR r.full_name ILIKE $%d
		)`, len(args), len(args), len(args), len(args), len(args), len(args), len(args))
	}

	var total int
	countQuery := `SELECT COUNT(*)` + filter
	if err := h.db.QueryRow(c.Request.Context(), countQuery, args...).Scan(&total); err != nil {
		h.log.Error("supply chain signals count", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	listArgs := append(append([]any{}, args...), perPage, offset)
	listQuery := `
		SELECT
			s.id, s.repo_id, s.signal_type, s.status, s.severity,
			s.package_ecosystem, s.package_name, s.package_version,
			s.source_engine, s.signal_key, s.signal_hash, s.confidence, s.reasoning,
			s.first_seen_at, s.last_seen_at, s.resolved_at, s.created_at, s.updated_at,
			COALESCE(r.full_name, '')
	` + filter + `
		ORDER BY s.last_seen_at DESC, s.created_at DESC
		LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)

	rows, err := h.db.Query(c.Request.Context(), listQuery, listArgs...)
	if err != nil {
		h.log.Error("supply chain signals list", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	items := make([]supplyChainSignalListItem, 0, perPage)
	for rows.Next() {
		var item supplyChainSignalListItem
		if err := rows.Scan(
			&item.ID, &item.RepoID, &item.SignalType, &item.Status, &item.Severity,
			&item.PackageEcosystem, &item.PackageName, &item.PackageVersion,
			&item.SourceEngine, &item.SignalKey, &item.SignalHash, &item.Confidence, &item.Reasoning,
			&item.FirstSeenAt, &item.LastSeenAt, &item.ResolvedAt, &item.CreatedAt, &item.UpdatedAt,
			&item.RepoFullName,
		); err != nil {
			continue
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, supplyChainSignalsListResponse{
		Items:   items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

func (h *SupplyChainSignalsHandler) summary(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var repoID *uuid.UUID
	if repoIDStr := strings.TrimSpace(c.Query("repo_id")); repoIDStr != "" {
		parsedID, parseErr := uuid.Parse(repoIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_id"})
			return
		}
		repoID = &parsedID
	}

	engine := strings.TrimSpace(c.Query("engine"))
	if engine != "" && !isValidSupplyChainSignalEngine(engine) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid engine"})
		return
	}

	status := strings.TrimSpace(c.Query("status"))
	if status != "" && !isValidSupplyChainSignalStatus(status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}

	signalType := strings.TrimSpace(c.Query("signal_type"))
	if signalType != "" && !isValidSupplyChainSignalType(signalType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid signal_type"})
		return
	}

	severity := strings.TrimSpace(c.Query("severity"))
	if severity != "" && !isValidSupplyChainSignalSeverity(severity) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
		return
	}

	args := []any{claims.TenantID}
	filter := ` FROM supply_chain_signals WHERE tenant_id = $1`
	if repoID != nil {
		args = append(args, *repoID)
		filter += fmt.Sprintf(" AND repo_id = $%d", len(args))
	}
	if engine != "" {
		args = append(args, engine)
		filter += fmt.Sprintf(" AND source_engine = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		filter += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if signalType != "" {
		args = append(args, signalType)
		filter += fmt.Sprintf(" AND signal_type = $%d", len(args))
	}
	if severity != "" {
		args = append(args, severity)
		filter += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		args = append(args, "%"+q+"%")
		filter += fmt.Sprintf(` AND (
			package_name ILIKE $%d
			OR package_version ILIKE $%d
			OR package_ecosystem ILIKE $%d
			OR reasoning ILIKE $%d
			OR signal_key ILIKE $%d
			OR signal_hash ILIKE $%d
			OR EXISTS (
				SELECT 1
				FROM repositories r
				WHERE r.id = supply_chain_signals.repo_id
				  AND r.full_name ILIKE $%d
			)
		)`, len(args), len(args), len(args), len(args), len(args), len(args), len(args))
	}

	var byStatusRaw, bySeverityRaw, bySignalTypeRaw, byEngineRaw []byte
	var summary supplyChainSignalsSummaryResponse

	err := h.db.QueryRow(c.Request.Context(), `
		SELECT
			base.total AS total,
			COALESCE((
				SELECT jsonb_object_agg(status, cnt)
				FROM (
					SELECT status, COUNT(*) AS cnt
					`+filter+`
					GROUP BY status
				) grouped_status
			), '{}'::jsonb) AS by_status,
			COALESCE((
				SELECT jsonb_object_agg(severity, cnt)
				FROM (
					SELECT severity, COUNT(*) AS cnt
					`+filter+`
					GROUP BY severity
				) grouped_severity
			), '{}'::jsonb) AS by_severity,
			COALESCE((
				SELECT jsonb_object_agg(signal_type, cnt)
				FROM (
					SELECT signal_type, COUNT(*) AS cnt
					`+filter+`
					GROUP BY signal_type
				) grouped_signal_type
			), '{}'::jsonb) AS by_signal_type,
			COALESCE((
				SELECT jsonb_object_agg(source_engine, cnt)
				FROM (
					SELECT source_engine, COUNT(*) AS cnt
					`+filter+`
					GROUP BY source_engine
				) grouped_engine
			), '{}'::jsonb) AS by_engine
		FROM (
			SELECT COUNT(*) AS total
			`+filter+`
		) base
	`, args...,
	).Scan(&summary.Total, &byStatusRaw, &bySeverityRaw, &bySignalTypeRaw, &byEngineRaw)
	if err != nil {
		h.log.Error("supply chain signals summary", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	summary.ByStatus = decodeJSONMap(byStatusRaw)
	summary.BySeverity = decodeJSONMap(bySeverityRaw)
	summary.BySignalType = decodeJSONMap(bySignalTypeRaw)
	summary.ByEngine = decodeJSONMap(byEngineRaw)

	c.JSON(http.StatusOK, summary)
}

func (h *SupplyChainSignalsHandler) get(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var out supplyChainSignalDetailResponse
	var evidenceRaw, metadataRaw []byte

	err = h.db.QueryRow(c.Request.Context(), `
		SELECT
			s.id, s.repo_id, s.signal_type, s.status, s.severity,
			s.package_ecosystem, s.package_name, s.package_version,
			s.source_engine, s.signal_key, s.signal_hash, s.confidence, s.reasoning,
			s.first_seen_at, s.last_seen_at, s.resolved_at, s.created_at, s.updated_at,
			COALESCE(r.full_name, ''),
			s.evidence_json, s.metadata_json
		FROM supply_chain_signals s
		LEFT JOIN repositories r ON r.id = s.repo_id
		WHERE s.tenant_id = $1 AND s.id = $2
	`,
		claims.TenantID, id,
	).Scan(
		&out.ID, &out.RepoID, &out.SignalType, &out.Status, &out.Severity,
		&out.PackageEcosystem, &out.PackageName, &out.PackageVersion,
		&out.SourceEngine, &out.SignalKey, &out.SignalHash, &out.Confidence, &out.Reasoning,
		&out.FirstSeenAt, &out.LastSeenAt, &out.ResolvedAt, &out.CreatedAt, &out.UpdatedAt,
		&out.RepoFullName,
		&evidenceRaw, &metadataRaw,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		h.log.Error("supply chain signal detail", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	out.Evidence = decodeJSONMap(evidenceRaw)
	out.Metadata = decodeJSONMap(metadataRaw)
	c.JSON(http.StatusOK, out)
}

func isValidSupplyChainSignalStatus(status string) bool {
	switch models.SupplyChainSignalStatus(status) {
	case models.SignalStatusOpen, models.SignalStatusTriaged, models.SignalStatusSuppressed, models.SignalStatusResolved:
		return true
	default:
		return false
	}
}

func isValidSupplyChainSignalType(signalType string) bool {
	switch models.SupplyChainSignalType(signalType) {
	case models.SignalTypeMaliciousPackage, models.SignalTypeTyposquat, models.SignalTypeDependencyConfusion, models.SignalTypeSuspiciousBehavior:
		return true
	default:
		return false
	}
}

func isValidSupplyChainSignalSeverity(severity string) bool {
	switch models.Severity(severity) {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityUnknown:
		return true
	default:
		return false
	}
}

func isValidSupplyChainSignalEngine(engine string) bool {
	switch engine {
	case "dataset", "guarddog", "openssf_pa", "manual":
		return true
	default:
		return false
	}
}
