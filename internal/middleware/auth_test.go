package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/response"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestJWTManager() *token.JWTManager {
	return token.NewJWTManager("test-access-secret", "test-refresh-secret", 15, 7)
}

func TestJWTAuth_Success(t *testing.T) {
	t.Parallel()

	jwtMgr := newTestJWTManager()
	app := fiber.New()
	app.Use(JWTAuth(jwtMgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"user_id":  c.Locals(ContextKeyUserID),
			"email":    c.Locals(ContextKeyEmail),
			"username": c.Locals(ContextKeyUsername),
		})
	})

	tokenStr, _, err := jwtMgr.GenerateAccessToken(42, "test@example.com", "testuser")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tokenStr})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	assert.Equal(t, float64(42), result["user_id"])
	assert.Equal(t, "test@example.com", result["email"])
	assert.Equal(t, "testuser", result["username"])
}

func TestJWTAuth_MissingToken(t *testing.T) {
	t.Parallel()

	jwtMgr := newTestJWTManager()
	app := fiber.New()
	app.Use(JWTAuth(jwtMgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(body, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "missing access token", result.Message)
}

func TestJWTAuth_InvalidToken(t *testing.T) {
	t.Parallel()

	jwtMgr := newTestJWTManager()
	app := fiber.New()
	app.Use(JWTAuth(jwtMgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "invalid-token"})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(body, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "invalid or expired token", result.Message)
}

func TestJWTAuth_WrongSecret(t *testing.T) {
	t.Parallel()

	jwtMgr := newTestJWTManager()
	differentMgr := token.NewJWTManager("different-secret", "different-refresh", 15, 7)

	tokenStr, _, err := differentMgr.GenerateAccessToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	app := fiber.New()
	app.Use(JWTAuth(jwtMgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tokenStr})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestJWTAuth_RefreshTokenNotAccepted(t *testing.T) {
	t.Parallel()

	jwtMgr := newTestJWTManager()

	refreshTokenStr, _, _, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	app := fiber.New()
	app.Use(JWTAuth(jwtMgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("should not reach here")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: refreshTokenStr})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}
