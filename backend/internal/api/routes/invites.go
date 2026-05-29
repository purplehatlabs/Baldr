package routes

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type InvitesHandler struct {
	invites         *auth.InviteStore
	memberships     *auth.MembershipStore
	session         *auth.SessionTokens
	db              *pgxpool.Pool
	log             *zap.Logger
	frontendBaseURL string
}

func NewInvitesHandler(cfg AuthHandlerConfig) *InvitesHandler {
	memberships := auth.NewMembershipStore(cfg.DB)
	return &InvitesHandler{
		invites:         auth.NewInviteStore(cfg.DB),
		memberships:     memberships,
		session:         auth.NewSessionTokens(cfg.Tokens, memberships),
		db:              cfg.DB,
		log:             cfg.Log,
		frontendBaseURL: strings.TrimRight(cfg.FrontendBaseURL, "/"),
	}
}

func (h *InvitesHandler) Register(r gin.IRouter, authMW gin.HandlerFunc) {
	admin := r.Group("/api/v1/invites", authMW, middleware.RequireAdmin())
	admin.POST("", h.create)
	admin.GET("", h.list)
	admin.DELETE("/:id", h.revoke)

	r.POST("/api/v1/invites/:token/accept", authMW, h.accept)
}

type createInviteRequest struct {
	Email string          `json:"email" binding:"required,email"`
	Role  models.UserRole `json:"role"`
}

func (h *InvitesHandler) create(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)

	var req createInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	role := req.Role
	if role == "" {
		role = models.RoleMember
	}
	switch role {
	case models.RoleOwner, models.RoleAdmin, models.RoleMember:
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}

	item, err := h.invites.Create(c.Request.Context(), claims.TenantID, claims.UserID, req.Email, role, h.frontendBaseURL)
	if err != nil {
		h.log.Error("create invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create invite"})
		return
	}

	c.JSON(http.StatusCreated, item)
}

func (h *InvitesHandler) list(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	items, err := h.invites.ListPending(c.Request.Context(), claims.TenantID)
	if err != nil {
		h.log.Error("list invites", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list invites"})
		return
	}
	if items == nil {
		items = []auth.InviteListItem{}
	}
	c.JSON(http.StatusOK, gin.H{"invites": items})
}

func (h *InvitesHandler) revoke(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	inviteID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invite id"})
		return
	}

	if err := h.invites.Revoke(c.Request.Context(), claims.TenantID, inviteID); err != nil {
		if errors.Is(err, auth.ErrInviteNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "invite not found"})
			return
		}
		h.log.Error("revoke invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke invite"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *InvitesHandler) accept(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	token := c.Param("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invite token"})
		return
	}

	var email string
	if err := h.db.QueryRow(c.Request.Context(), `SELECT email FROM users WHERE id = $1`, claims.UserID).Scan(&email); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	membership, err := h.invites.Accept(c.Request.Context(), token, claims.UserID, email)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInviteNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "invite not found"})
		case errors.Is(err, auth.ErrInviteExpired):
			c.JSON(http.StatusGone, gin.H{"error": "invite expired"})
		case errors.Is(err, auth.ErrInviteEmailMismatch):
			c.JSON(http.StatusForbidden, gin.H{"error": "invite email does not match your account"})
		default:
			h.log.Error("accept invite", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not accept invite"})
		}
		return
	}

	user := models.User{ID: claims.UserID, Email: email}
	tokenStr, err := h.session.IssueForMembership(c.Request.Context(), &user, membership)
	if err != nil {
		h.log.Error("issue token after invite accept", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}

	c.SetCookie("access_token", tokenStr, int(24*time.Hour.Seconds()), "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"active_tenant_id": membership.TenantID,
		"role":             membership.Role,
	})
}
