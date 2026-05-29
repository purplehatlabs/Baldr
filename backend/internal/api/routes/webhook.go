package routes

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/models"
	repositoriesvc "github.com/purplehatlabs/Baldr/internal/repositories"
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
	// For now just trigger a scan on the default branch push
	// A full implementation would parse the push payload to get the repo full_name
	// and look up the repo ID in our DB.
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

// EnqueueWebhookScan triggers a scan for a repo identified by its GitHub full_name.
func (h *WebhookHandler) enqueueByFullName(ctx *gin.Context, fullName string) {
	rows, err := h.db.Query(ctx.Request.Context(), `
		SELECT id FROM repositories WHERE full_name = $1 AND is_archived = FALSE`, fullName,
	)
	if err != nil {
		h.log.Warn("webhook: repo not found", zap.String("full_name", fullName))
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		found = true
		var repoID uuid.UUID
		if err := rows.Scan(&repoID); err != nil {
			continue
		}
		if err := h.scheduler.EnqueueRepo(repoID, models.TriggerWebhook); err != nil {
			if errors.Is(err, repositoriesvc.ErrScanBlockedMissingInternetExposure) {
				h.log.Info("webhook: scan blocked due to missing exposure", zap.String("repo_id", repoID.String()))
				continue
			}
			if errors.Is(err, repositoriesvc.ErrScanAlreadyQueuedOrRunning) {
				h.log.Debug("webhook: scan already queued or running", zap.String("repo_id", repoID.String()))
				continue
			}
			h.log.Warn("webhook: enqueue failed", zap.String("repo_id", repoID.String()), zap.Error(err))
		}
	}
	if !found {
		h.log.Warn("webhook: repo not found", zap.String("full_name", fullName))
	}
}
