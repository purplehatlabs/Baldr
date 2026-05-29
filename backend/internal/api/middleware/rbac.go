package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/purplehatlabs/Baldr/internal/models"
)

// HasRole returns true when claims include one of the allowed roles.
func HasRole(claimsRole string, allowed ...models.UserRole) bool {
	for _, r := range allowed {
		if claimsRole == string(r) {
			return true
		}
	}
	return false
}

// RequireRole aborts with 403 unless the JWT role is in allowed.
func RequireRole(allowed ...models.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFrom(c)
		if claims == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if !HasRole(claims.Role, allowed...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
		c.Next()
	}
}

// RequireAdmin is shorthand for owner or admin.
func RequireAdmin() gin.HandlerFunc {
	return RequireRole(models.RoleOwner, models.RoleAdmin)
}
