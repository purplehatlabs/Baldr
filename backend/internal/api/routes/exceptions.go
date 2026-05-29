package routes

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	findingsvc "github.com/purplehatlabs/Baldr/internal/findings"
	"go.uber.org/zap"
)

type ExceptionsHandler struct {
	db             *pgxpool.Pool
	log            *zap.Logger
	prioritization *findingsvc.PrioritizationService
}

func NewExceptionsHandler(db *pgxpool.Pool, log *zap.Logger) *ExceptionsHandler {
	return &ExceptionsHandler{
		db:             db,
		log:            log,
		prioritization: findingsvc.NewPrioritizationService(db),
	}
}

func (h *ExceptionsHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/exceptions", authMW)
	g.GET("", h.list)
	g.POST("", h.create)
	g.PUT("/:id", h.update)
}

type findingExceptionResponse struct {
	ID               uuid.UUID  `json:"id"`
	FindingID        uuid.UUID  `json:"finding_id"`
	Reason           string     `json:"reason"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ApprovedByUserID *uuid.UUID `json:"approved_by_user_id,omitempty"`
	CreatedByUserID  *uuid.UUID `json:"created_by_user_id,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

func (h *ExceptionsHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	findingID := c.Query("finding_id")

	query := `
		SELECT fe.id, fe.finding_id, fe.reason, fe.expires_at, fe.approved_by_user_id,
		       fe.created_by_user_id, fe.created_at, fe.updated_at
		FROM finding_exceptions fe
		WHERE fe.tenant_id = $1`
	args := []any{claims.TenantID}

	if findingID != "" {
		query += ` AND fe.finding_id = $2`
		args = append(args, findingID)
	}
	query += ` ORDER BY fe.created_at DESC`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.log.Error("list exceptions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	items := make([]findingExceptionResponse, 0)
	for rows.Next() {
		var item findingExceptionResponse
		if err := rows.Scan(
			&item.ID, &item.FindingID, &item.Reason, &item.ExpiresAt, &item.ApprovedByUserID,
			&item.CreatedByUserID, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			continue
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, items)
}

type createExceptionRequest struct {
	FindingID        uuid.UUID  `json:"finding_id" binding:"required"`
	Reason           string     `json:"reason" binding:"required"`
	ExpiresAt        *time.Time `json:"expires_at"`
	ApprovedByUserID *uuid.UUID `json:"approved_by_user_id"`
}

func (h *ExceptionsHandler) create(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req createExceptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	expiresAt := req.ExpiresAt
	if expiresAt == nil {
		defaultExpiry := time.Now().UTC().Add(30 * 24 * time.Hour)
		expiresAt = &defaultExpiry
	}
	if expiresAt.Before(time.Now().UTC()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be in the future"})
		return
	}

	var exists bool
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS (
			SELECT 1
			FROM findings f
			JOIN manifests m ON m.id = f.manifest_id
			JOIN repositories r ON r.id = m.repo_id
			JOIN organizations o ON o.id = r.org_id
			WHERE f.id = $1 AND o.tenant_id = $2
		)`,
		req.FindingID, claims.TenantID,
	).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}

	var id uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO finding_exceptions
			(tenant_id, finding_id, reason, expires_at, approved_by_user_id, created_by_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING id`,
		claims.TenantID, req.FindingID, req.Reason, expiresAt, req.ApprovedByUserID, claims.UserID,
	).Scan(&id)
	if err != nil {
		h.log.Error("create exception", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := h.prioritization.RecalculateRiskScore(c.Request.Context(), req.FindingID, claims.TenantID); err != nil {
		h.log.Warn("recalculate risk score after exception", zap.Error(err))
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

type updateExceptionRequest struct {
	Reason           string     `json:"reason" binding:"required"`
	ExpiresAt        *time.Time `json:"expires_at"`
	ApprovedByUserID *uuid.UUID `json:"approved_by_user_id"`
}

func (h *ExceptionsHandler) update(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	exceptionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var req updateExceptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now().UTC()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be in the future"})
		return
	}

	var findingID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		UPDATE finding_exceptions
		SET reason = $1, expires_at = $2, approved_by_user_id = $3, updated_at = NOW()
		WHERE id = $4 AND tenant_id = $5
		RETURNING finding_id`,
		req.Reason, req.ExpiresAt, req.ApprovedByUserID, exceptionID, claims.TenantID,
	).Scan(&findingID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		h.log.Error("update exception", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	if err := h.prioritization.RecalculateRiskScore(c.Request.Context(), findingID, claims.TenantID); err != nil {
		h.log.Warn("recalculate risk score after exception update", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}
