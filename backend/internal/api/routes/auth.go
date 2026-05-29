package routes

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/i18n"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type AuthHandler struct {
	google          *auth.GoogleProvider
	github          *auth.GitHubProvider
	users           *auth.UserStore
	tokens          *auth.TokenService
	db              *pgxpool.Pool
	log             *zap.Logger
	frontendBaseURL string
	googleEnabled   bool
	githubEnabled   bool
}

type AuthHandlerConfig struct {
	Google          *auth.GoogleProvider
	GitHub          *auth.GitHubProvider
	Tokens          *auth.TokenService
	DB              *pgxpool.Pool
	Log             *zap.Logger
	FrontendBaseURL string
	GoogleEnabled   bool
	GitHubEnabled   bool
}

func NewAuthHandler(cfg AuthHandlerConfig) *AuthHandler {
	return &AuthHandler{
		google:          cfg.Google,
		github:          cfg.GitHub,
		users:           auth.NewUserStore(cfg.DB),
		tokens:          cfg.Tokens,
		db:              cfg.DB,
		log:             cfg.Log,
		frontendBaseURL: strings.TrimRight(cfg.FrontendBaseURL, "/"),
		googleEnabled:   cfg.GoogleEnabled,
		githubEnabled:   cfg.GitHubEnabled,
	}
}

func (h *AuthHandler) Register(r gin.IRouter) {
	if h.githubEnabled && h.github != nil {
		r.GET("/auth/github", h.redirectToGitHub)
		r.GET("/auth/github/callback", h.handleGitHubCallback)
	}
	if h.googleEnabled && h.google != nil {
		r.GET("/auth/google", h.redirectToGoogle)
		r.GET("/auth/google/callback", h.handleGoogleCallback)
	}
	r.POST("/auth/logout", h.logout)
}

func (h *AuthHandler) RegisterProtected(r gin.IRouter, authMW gin.HandlerFunc) {
	r.GET("/auth/me", authMW, h.me)
	r.PATCH("/auth/me/preferences", authMW, h.updatePreferences)
}

func (h *AuthHandler) redirectToGitHub(c *gin.Context) {
	if h.github == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "GitHub SSO is not enabled"})
		return
	}
	state := randomState()
	c.SetCookie("oauth_state", state, 300, "/", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, h.github.AuthURL(state))
}

func (h *AuthHandler) redirectToGoogle(c *gin.Context) {
	if h.google == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Google SSO is not enabled"})
		return
	}
	state := randomState()
	c.SetCookie("oauth_state", state, 300, "/", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, h.google.AuthURL(state))
}

func (h *AuthHandler) handleGitHubCallback(c *gin.Context) {
	if !h.validateOAuthState(c) {
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	userInfo, err := h.github.Exchange(c.Request.Context(), code)
	if err != nil {
		h.log.Error("github exchange failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	user, err := h.users.UpsertGitHubUser(c.Request.Context(), userInfo)
	if err != nil {
		if errors.Is(err, auth.ErrMissingEmail) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "GitHub account has no verified email"})
			return
		}
		h.log.Error("upsert github user failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}

	h.finishLogin(c, user)
}

func (h *AuthHandler) handleGoogleCallback(c *gin.Context) {
	if !h.validateOAuthState(c) {
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	userInfo, err := h.google.Exchange(c.Request.Context(), code)
	if err != nil {
		h.log.Error("google exchange failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	user, err := h.users.UpsertGoogleUser(c.Request.Context(), userInfo)
	if err != nil {
		h.log.Error("upsert google user failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}

	h.finishLogin(c, user)
}

func (h *AuthHandler) validateOAuthState(c *gin.Context) bool {
	expectedState, err := c.Cookie("oauth_state")
	if err != nil || expectedState != c.Query("state") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return false
	}
	return true
}

func (h *AuthHandler) finishLogin(c *gin.Context, user *models.User) {
	tokenStr, err := h.tokens.Issue(user.ID, user.TenantID, user.Email, string(user.Role))
	if err != nil {
		h.log.Error("issue token failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}

	c.SetCookie("access_token", tokenStr, int(24*time.Hour.Seconds()), "/", "", false, true)
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	redirectTo := h.frontendBaseURL + "/"
	if h.frontendBaseURL == "" {
		redirectTo = "/"
	}
	c.Redirect(http.StatusTemporaryRedirect, redirectTo)
}

func (h *AuthHandler) logout(c *gin.Context) {
	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthHandler) me(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var user models.User
	err := h.db.QueryRow(c.Request.Context(),
		`SELECT id, tenant_id, email, name, avatar_url, role, COALESCE(NULLIF(language, ''), 'en'), created_at
		 FROM users WHERE id = $1 AND tenant_id = $2`,
		claims.UserID, claims.TenantID,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.Name, &user.AvatarURL, &user.Role, &user.Language, &user.CreatedAt)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	user.Language = i18n.ParseLocale(user.Language)

	c.JSON(http.StatusOK, user)
}

type updatePreferencesRequest struct {
	Language *string `json:"language"`
}

func (h *AuthHandler) updatePreferences(c *gin.Context) {
	claims := middleware.ClaimsFrom(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req updatePreferencesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Language == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "language is required"})
		return
	}

	locale := i18n.ParseLocale(*req.Language)
	tag, err := h.db.Exec(c.Request.Context(),
		`UPDATE users SET language = $1 WHERE id = $2 AND tenant_id = $3`,
		locale, claims.UserID, claims.TenantID,
	)
	if err != nil {
		h.log.Error("update user preferences", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update preferences"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"language": locale})
}

func randomState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
