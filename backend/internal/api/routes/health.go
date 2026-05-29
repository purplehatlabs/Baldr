package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RegisterHealth(r gin.IRouter) {
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}
