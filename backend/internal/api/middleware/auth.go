package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/purplehatlabs/Baldr/internal/auth"
)

const (
	ContextKeyUser     = "user_claims"
	cookieName         = "access_token"
)

func Auth(tokens *auth.TokenService) gin.HandlerFunc {
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

		c.Set(ContextKeyUser, claims)
		c.Next()
	}
}

func extractToken(c *gin.Context) string {
	// 1. httpOnly cookie
	if cookie, err := c.Cookie(cookieName); err == nil && cookie != "" {
		return cookie
	}
	// 2. Authorization: Bearer <token> header (for API clients)
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
