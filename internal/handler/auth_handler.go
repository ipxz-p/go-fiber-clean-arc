package handler

import (
	"time"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/usecase"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/response"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/validator"

	"github.com/gofiber/fiber/v2"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"
)

type AuthHandler struct {
	authUsecase usecase.AuthUsecase
	validator   *validator.Validator
}

func NewAuthHandler(authUsecase usecase.AuthUsecase, validator *validator.Validator) *AuthHandler {
	return &AuthHandler{
		authUsecase: authUsecase,
		validator:   validator,
	}
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var input usecase.LoginInput

	if err := c.BodyParser(&input); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "invalid request body")
	}

	if errs := h.validator.Validate(input); errs != nil {
		return response.ValidationError(c, "validation failed", errs)
	}

	output, err := h.authUsecase.Login(c.UserContext(), input)
	if err != nil {
		return err
	}

	h.setAccessTokenCookie(c, output.AccessToken, output.AccessTokenExpiresAt)
	h.setRefreshTokenCookie(c, output.RefreshToken, output.RefreshTokenExpiresAt)

	return response.Success(c, fiber.StatusOK, "login successful", nil)
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	refreshToken := c.Cookies(refreshTokenCookie)
	if refreshToken == "" {
		return response.Error(c, fiber.StatusBadRequest, "no refresh token found")
	}

	if err := h.authUsecase.Logout(c.UserContext(), refreshToken); err != nil {
		return err
	}

	h.clearAccessTokenCookie(c)
	h.clearRefreshTokenCookie(c)

	return response.Success(c, fiber.StatusOK, "logout successful", nil)
}

func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	refreshToken := c.Cookies(refreshTokenCookie)
	if refreshToken == "" {
		return response.Error(c, fiber.StatusUnauthorized, "no refresh token found")
	}

	output, err := h.authUsecase.RefreshToken(c.UserContext(), refreshToken)
	if err != nil {
		return err
	}

	h.setAccessTokenCookie(c, output.AccessToken, output.AccessTokenExpiresAt)

	return response.Success(c, fiber.StatusOK, "token refreshed", nil)
}

func (h *AuthHandler) setAccessTokenCookie(c *fiber.Ctx, token string, expiresAt time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     accessTokenCookie,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}

func (h *AuthHandler) clearAccessTokenCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     accessTokenCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}

func (h *AuthHandler) setRefreshTokenCookie(c *fiber.Ctx, token string, expiresAt time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     refreshTokenCookie,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}

func (h *AuthHandler) clearRefreshTokenCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}
