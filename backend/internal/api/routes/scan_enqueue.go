package routes

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	repositoriesvc "github.com/purplehatlabs/Baldr/internal/repositories"
)

// respondScanEnqueueError writes the appropriate HTTP response for scan enqueue
// failures. Optional extra fields (e.g. repo_id) are merged into the body.
// Returns true when err was handled.
func respondScanEnqueueError(c *gin.Context, err error, extra ...gin.H) bool {
	var code string
	switch {
	case errors.Is(err, repositoriesvc.ErrScanBlockedMissingInternetExposure):
		code = "scan_blocked_missing_internet_exposure"
	case errors.Is(err, repositoriesvc.ErrScanAlreadyQueuedOrRunning):
		code = "scan_already_queued_or_running"
	default:
		return false
	}

	body := gin.H{"error": code, "code": code}
	if len(extra) > 0 {
		for k, v := range extra[0] {
			body[k] = v
		}
	}
	c.JSON(http.StatusConflict, body)
	return true
}
