package routes

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/scheduler"
	"go.uber.org/zap"
)

type WebhookHandler struct {
	db            *pgxpool.Pool
	scheduler     *scheduler.OrgScheduler
	webhookSecret string
	log           *zap.Logger
}

func NewWebhookHandler(db *pgxpool.Pool, sched *scheduler.OrgScheduler, secret string, log *zap.Logger) *WebhookHandler {
	return &WebhookHandler{db: db, scheduler: sched, webhookSecret: secret, log: log}
}

func (h *WebhookHandler) Register(r gin.IRouter) {
	r.POST("/webhooks/github", h.handle)
}

func (h *WebhookHandler) handle(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	if !h.verifySignature(body, c.GetHeader("X-Hub-Signature-256")) {
		c.Status(http.StatusUnauthorized)
		return
	}

	event := c.GetHeader("X-GitHub-Event")
	switch event {
	case "push":
		h.handlePush(c, body)
	case "installation":
		// TODO: handle app installation/uninstallation events
		c.Status(http.StatusOK)
	default:
		c.Status(http.StatusOK)
	}
}

func (h *WebhookHandler) handlePush(c *gin.Context, _ []byte) {
	// Resolve organization + tenant_id from the GitHub payload before enqueueing scans or
	// mutating tenant-scoped rows. Never trust repo/org identifiers without a tenant_id check.
	c.Status(http.StatusOK)
}

// verifySignature validates the HMAC-SHA256 signature from GitHub.
func (h *WebhookHandler) verifySignature(body []byte, sig string) bool {
	if h.webhookSecret == "" {
		return true // no secret configured, skip validation (dev mode)
	}
	if len(sig) < 7 || sig[:7] != "sha256=" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(h.webhookSecret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}
