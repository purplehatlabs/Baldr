package routes

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type MembersHandler struct {
	memberships *auth.MembershipStore
	log         *zap.Logger
}

func NewMembersHandler(db *pgxpool.Pool, log *zap.Logger) *MembersHandler {
	return &MembersHandler{
		memberships: auth.NewMembershipStore(db),
		log:         log,
	}
}

func (h *MembersHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	g := r.Group("/api/v1/members", authMW, middleware.RequireAdmin())
	g.GET("", h.list)
	g.PATCH("/:id", h.update)
}

func (h *MembersHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	items, err := h.memberships.ListMembers(c.Request.Context(), claims.TenantID)
	if err != nil {
		h.log.Error("list members", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list members"})
		return
	}
	if items == nil {
		items = []auth.MemberListItem{}
	}
	c.JSON(http.StatusOK, gin.H{"members": items})
}

type updateMemberRequest struct {
	Role   *models.UserRole         `json:"role"`
	Status *models.MembershipStatus `json:"status"`
}

func (h *MembersHandler) update(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	membershipID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid membership id"})
		return
	}

	var req updateMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Role != nil {
		switch *req.Role {
		case models.RoleOwner, models.RoleAdmin, models.RoleMember:
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
			return
		}
	}
	if req.Status != nil {
		switch *req.Status {
		case models.MembershipActive, models.MembershipInactive:
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
			return
		}
	}

	item, err := h.memberships.UpdateMember(c.Request.Context(), claims.TenantID, membershipID, req.Role, req.Status)
	if err != nil {
		if errors.Is(err, auth.ErrMembershipNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
			return
		}
		h.log.Error("update member", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update member"})
		return
	}

	c.JSON(http.StatusOK, item)
}
