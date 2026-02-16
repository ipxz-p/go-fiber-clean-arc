package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/middleware"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/usecase"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/response"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/validator"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)


type mockAuthUsecase struct {
	mock.Mock
}

func (m *mockAuthUsecase) Login(ctx context.Context, input usecase.LoginInput) (*usecase.TokenOutput, error) {
	args := m.Called(ctx, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.TokenOutput), args.Error(1)
}

func (m *mockAuthUsecase) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func (m *mockAuthUsecase) RefreshToken(ctx context.Context, refreshToken string) (*usecase.TokenOutput, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.TokenOutput), args.Error(1)
}


func setupAuthTestApp(mockUC *mockAuthUsecase) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: middleware.ErrorHandler,
	})
	v := validator.New()
	h := NewAuthHandler(mockUC, v)

	app.Post("/login", h.Login)
	app.Post("/logout", h.Logout)
	app.Post("/refresh", h.RefreshToken)
	return app
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}


func TestAuthHandler_Login_Success(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	tokenOutput := &usecase.TokenOutput{
		AccessToken:           "access-token-value",
		AccessTokenExpiresAt:  time.Now().Add(15 * time.Minute),
		RefreshToken:          "refresh-token-value",
		RefreshTokenExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	input := usecase.LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	}
	mockUC.On("Login", mock.Anything, input).Return(tokenOutput, nil)

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.SuccessResponse
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	assert.True(t, result.Success)
	assert.Equal(t, "login successful", result.Message)

	accessCookie := findCookie(resp.Cookies(), "access_token")
	refreshCookie := findCookie(resp.Cookies(), "refresh_token")
	require.NotNil(t, accessCookie)
	require.NotNil(t, refreshCookie)
	assert.Equal(t, "access-token-value", accessCookie.Value)
	assert.Equal(t, "refresh-token-value", refreshCookie.Value)
	assert.True(t, accessCookie.HttpOnly)
	assert.True(t, refreshCookie.HttpOnly)
	mockUC.AssertExpectations(t)
}

func TestAuthHandler_Login_InvalidBody(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader([]byte("bad json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(respBody, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "invalid request body", result.Message)
	mockUC.AssertNotCalled(t, "Login")
}

func TestAuthHandler_Login_ValidationError(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	input := map[string]string{
		"email":    "not-an-email",
		"password": "",
	}
	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnprocessableEntity, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(respBody, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "validation failed", result.Message)
	assert.NotEmpty(t, result.Errors)
	mockUC.AssertNotCalled(t, "Login")
}

func TestAuthHandler_Login_UsecaseError(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	input := usecase.LoginInput{
		Email:    "wrong@example.com",
		Password: "password123",
	}
	mockUC.On("Login", mock.Anything, input).Return(nil, apperror.New(http.StatusUnauthorized, "invalid email or password"))

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(respBody, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "invalid email or password", result.Message)
	mockUC.AssertExpectations(t)
}


func TestAuthHandler_Logout_Success(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	mockUC.On("Logout", mock.Anything, "my-refresh-token").Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "my-refresh-token"})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.SuccessResponse
	json.Unmarshal(respBody, &result)

	assert.True(t, result.Success)
	assert.Equal(t, "logout successful", result.Message)

	accessCookie := findCookie(resp.Cookies(), "access_token")
	refreshCookie := findCookie(resp.Cookies(), "refresh_token")
	if accessCookie != nil {
		assert.Empty(t, accessCookie.Value)
	}
	if refreshCookie != nil {
		assert.Empty(t, refreshCookie.Value)
	}
	mockUC.AssertExpectations(t)
}

func TestAuthHandler_Logout_NoCookie(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(respBody, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "no refresh token found", result.Message)
	mockUC.AssertNotCalled(t, "Logout")
}

func TestAuthHandler_Logout_UsecaseError(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	mockUC.On("Logout", mock.Anything, "bad-token").Return(apperror.New(http.StatusBadRequest, "invalid refresh token"))

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "bad-token"})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(respBody, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "invalid refresh token", result.Message)
	mockUC.AssertExpectations(t)
}

// --- RefreshToken Tests ---

func TestAuthHandler_RefreshToken_Success(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	tokenOutput := &usecase.TokenOutput{
		AccessToken:          "new-access-token",
		AccessTokenExpiresAt: time.Now().Add(15 * time.Minute),
	}
	mockUC.On("RefreshToken", mock.Anything, "valid-refresh-token").Return(tokenOutput, nil)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "valid-refresh-token"})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.SuccessResponse
	json.Unmarshal(respBody, &result)

	assert.True(t, result.Success)
	assert.Equal(t, "token refreshed", result.Message)

	accessCookie := findCookie(resp.Cookies(), "access_token")
	require.NotNil(t, accessCookie)
	assert.Equal(t, "new-access-token", accessCookie.Value)
	mockUC.AssertExpectations(t)
}

func TestAuthHandler_RefreshToken_NoCookie(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(respBody, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "no refresh token found", result.Message)
	mockUC.AssertNotCalled(t, "RefreshToken")
}

func TestAuthHandler_RefreshToken_UsecaseError(t *testing.T) {
	t.Parallel()

	mockUC := new(mockAuthUsecase)
	app := setupAuthTestApp(mockUC)

	mockUC.On("RefreshToken", mock.Anything, "expired-token").Return(nil, apperror.New(http.StatusUnauthorized, "invalid or expired refresh token"))

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "expired-token"})

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	json.Unmarshal(respBody, &result)

	assert.False(t, result.Success)
	assert.Equal(t, "invalid or expired refresh token", result.Message)
	mockUC.AssertExpectations(t)
}
