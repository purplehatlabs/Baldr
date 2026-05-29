package routes

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"go.uber.org/zap"
)

type PoliciesHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewPoliciesHandler(db *pgxpool.Pool, log *zap.Logger) *PoliciesHandler {
	return &PoliciesHandler{db: db, log: log}
}

func (h *PoliciesHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/policies", authMW)
	g.GET("", h.list)
	g.POST("", h.create)
	g.PUT("/:id", h.update)
	g.DELETE("/:id", h.delete)
}

type policyRulePayload struct {
	RuleType string         `json:"rule_type" binding:"required"`
	Field    string         `json:"field" binding:"required"`
	Operator string         `json:"operator" binding:"required"`
	Value    map[string]any `json:"value"`
}

type policyPayload struct {
	ID          uuid.UUID           `json:"id,omitempty"`
	Name        string              `json:"name" binding:"required"`
	Description string              `json:"description"`
	IsEnabled   bool                `json:"is_enabled"`
	Rules       []policyRulePayload `json:"rules"`
	CreatedAt   time.Time           `json:"created_at,omitempty"`
	UpdatedAt   time.Time           `json:"updated_at,omitempty"`
}

func (h *PoliciesHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, name, description, is_enabled, created_at, updated_at
		FROM policies
		WHERE tenant_id = $1
		ORDER BY name`, claims.TenantID)
	if err != nil {
		h.log.Error("list policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	resp := make([]policyPayload, 0)
	policyIDs := make([]uuid.UUID, 0)
	byID := map[uuid.UUID]int{}

	for rows.Next() {
		var p policyPayload
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.IsEnabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		p.Rules = []policyRulePayload{}
		byID[p.ID] = len(resp)
		resp = append(resp, p)
		policyIDs = append(policyIDs, p.ID)
	}

	if len(policyIDs) > 0 {
		ruleRows, err := h.db.Query(c.Request.Context(), `
			SELECT policy_id, rule_type, field, operator, value_json
			FROM policy_rules
			WHERE tenant_id = $1 AND policy_id = ANY($2)
			ORDER BY created_at`, claims.TenantID, policyIDs)
		if err == nil {
			defer ruleRows.Close()
			for ruleRows.Next() {
				var (
					policyID uuid.UUID
					rule     policyRulePayload
					raw      []byte
				)
				if err := ruleRows.Scan(&policyID, &rule.RuleType, &rule.Field, &rule.Operator, &raw); err != nil {
					continue
				}
				if len(raw) > 0 {
					_ = json.Unmarshal(raw, &rule.Value)
				}
				if rule.Value == nil {
					rule.Value = map[string]any{}
				}
				if idx, ok := byID[policyID]; ok {
					resp[idx].Rules = append(resp[idx].Rules, rule)
				}
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

type createPolicyRequest struct {
	Name        string              `json:"name" binding:"required"`
	Description string              `json:"description"`
	IsEnabled   *bool               `json:"is_enabled"`
	Rules       []policyRulePayload `json:"rules"`
}

func (h *PoliciesHandler) create(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req createPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	enabled := true
	if req.IsEnabled != nil {
		enabled = *req.IsEnabled
	}

	tx, err := h.db.Begin(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer func() { _ = tx.Rollback(c.Request.Context()) }()

	var policyID uuid.UUID
	err = tx.QueryRow(c.Request.Context(), `
		INSERT INTO policies (tenant_id, name, description, is_enabled, created_by_user_id, updated_by_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5, NOW(), NOW())
		RETURNING id`,
		claims.TenantID, req.Name, req.Description, enabled, claims.UserID,
	).Scan(&policyID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not create policy"})
		return
	}

	for _, rule := range req.Rules {
		if rule.Value == nil {
			rule.Value = map[string]any{}
		}
		valueJSON, _ := json.Marshal(rule.Value)
		if _, err := tx.Exec(c.Request.Context(), `
			INSERT INTO policy_rules (tenant_id, policy_id, rule_type, field, operator, value_json, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
			claims.TenantID, policyID, rule.RuleType, rule.Field, rule.Operator, valueJSON,
		); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "could not create policy rules"})
			return
		}
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": policyID})
}

type updatePolicyRequest struct {
	Name        string              `json:"name" binding:"required"`
	Description string              `json:"description"`
	IsEnabled   bool                `json:"is_enabled"`
	Rules       []policyRulePayload `json:"rules"`
}

func (h *PoliciesHandler) update(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var req updatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx, err := h.db.Begin(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer func() { _ = tx.Rollback(c.Request.Context()) }()

	result, err := tx.Exec(c.Request.Context(), `
		UPDATE policies
		SET name = $1, description = $2, is_enabled = $3, updated_by_user_id = $4, updated_at = NOW()
		WHERE id = $5 AND tenant_id = $6`,
		req.Name, req.Description, req.IsEnabled, claims.UserID, policyID, claims.TenantID,
	)
	if err != nil || result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	if _, err := tx.Exec(c.Request.Context(),
		`DELETE FROM policy_rules WHERE tenant_id = $1 AND policy_id = $2`,
		claims.TenantID, policyID,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	for _, rule := range req.Rules {
		if rule.Value == nil {
			rule.Value = map[string]any{}
		}
		valueJSON, _ := json.Marshal(rule.Value)
		if _, err := tx.Exec(c.Request.Context(), `
			INSERT INTO policy_rules (tenant_id, policy_id, rule_type, field, operator, value_json, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
			claims.TenantID, policyID, rule.RuleType, rule.Field, rule.Operator, valueJSON,
		); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "could not update policy rules"})
			return
		}
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *PoliciesHandler) delete(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM policies
		WHERE id = $1 AND tenant_id = $2`,
		policyID, claims.TenantID,
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
