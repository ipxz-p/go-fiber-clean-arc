package middleware

import (
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/response"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/token"

	"github.com/gofiber/fiber/v2"
)

const (
	ContextKeyUserID   = "user_id"
	ContextKeyEmail    = "email"
	ContextKeyUsername = "username"
)

func JWTAuth(jwt *token.JWTManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := c.Cookies("access_token")
		if tokenString == "" {
			return response.Error(c, fiber.StatusUnauthorized, "missing access token")
		}

		claims, err := jwt.ValidateAccessToken(tokenString)
		if err != nil {
			return response.Error(c, fiber.StatusUnauthorized, "invalid or expired token")
		}

		c.Locals(ContextKeyUserID, claims.UserID)
		c.Locals(ContextKeyEmail, claims.Email)
		c.Locals(ContextKeyUsername, claims.Username)

		return c.Next()
	}
}
