package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/purplehatlabs/Baldr/internal/auth"
)

const (
	ContextKeyUser = "user_claims"
	cookieName     = "access_token"
)

// Auth validates JWT and active membership token_version (rejects stale sessions).
func Auth(tokens *auth.TokenService, memberships *auth.MembershipStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		claims, err := tokens.Validate(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		if err := memberships.ValidateSession(c.Request.Context(), claims.TenantID, claims.UserID, claims.TokenVersion); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
			return
		}

		c.Set(ContextKeyUser, claims)
		c.Next()
	}
}

func extractToken(c *gin.Context) string {
	if cookie, err := c.Cookie(cookieName); err == nil && cookie != "" {
		return cookie
	}
	header := c.GetHeader("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return ""
}

// ClaimsFrom retrieves the validated JWT claims from the Gin context.
func ClaimsFrom(c *gin.Context) *auth.Claims {
	v, _ := c.Get(ContextKeyUser)
	claims, _ := v.(*auth.Claims)
	return claims
}
