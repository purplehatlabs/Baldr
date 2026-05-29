package routes

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type DevAuthHandler struct {
	tokens *auth.TokenService
	db     *pgxpool.Pool
	log    *zap.Logger
}

func NewDevAuthHandler(tokens *auth.TokenService, db *pgxpool.Pool, log *zap.Logger) *DevAuthHandler {
	return &DevAuthHandler{tokens: tokens, db: db, log: log}
}

func (h *DevAuthHandler) Register(r gin.IRouter) {
	r.POST("/auth/dev/login", h.login)
}

type devLoginRequest struct {
	Email string `json:"email" binding:"required,email"`
	Name  string `json:"name"`
}

func (h *DevAuthHandler) login(c *gin.Context) {
	var req devLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	name := req.Name
	if name == "" {
		name = strings.Split(req.Email, "@")[0]
	}

	user, err := h.upsertDevUser(c.Request.Context(), req.Email, name)
	if err != nil {
		h.log.Error("dev login: upsert user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}

	tokenStr, err := h.tokens.Issue(user.ID, user.TenantID, user.Email, string(user.Role))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}

	c.SetCookie("access_token", tokenStr, int(24*time.Hour.Seconds()), "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true, "user": user})
}

func (h *DevAuthHandler) upsertDevUser(ctx context.Context, email, name string) (*models.User, error) {
	var user models.User

	err := h.db.QueryRow(ctx,
		`SELECT id, tenant_id, email, name, avatar_url, role, created_at
		 FROM users WHERE email = $1`, email,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.Name, &user.AvatarURL, &user.Role, &user.CreatedAt)

	if err == nil {
		return &user, nil
	}

	// New user — create tenant + user
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	tenantID := uuid.New()
	_, err = tx.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		tenantID, email, tenantID.String(),
	)
	if err != nil {
		return nil, err
	}

	userID := uuid.New()
	// dev users get a generated google_id so the unique constraint is satisfied
	devGoogleID := "dev:" + userID.String()
	_, err = tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, google_id, name, avatar_url, role, auth_provider, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
		userID, tenantID, email, devGoogleID, name, "", models.RoleOwner, auth.AuthProviderDev,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &models.User{
		ID: userID, TenantID: tenantID,
		Email: email, Name: name, Role: models.RoleOwner,
	}, nil
}
