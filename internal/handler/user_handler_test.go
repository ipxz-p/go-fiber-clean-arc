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


type mockUserUsecase struct {
	mock.Mock
}

func (m *mockUserUsecase) Register(ctx context.Context, input usecase.RegisterInput) (*usecase.RegisterOutput, error) {
	args := m.Called(ctx, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.RegisterOutput), args.Error(1)
}


func setupUserTestApp(mockUC *mockUserUsecase) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: middleware.ErrorHandler,
	})
	v := validator.New()
	h := NewUserHandler(mockUC, v)
	app.Post("/register", h.Register)
	return app
}


func TestUserHandler_Register_Success(t *testing.T) {
	t.Parallel()

	mockUC := new(mockUserUsecase)
	app := setupUserTestApp(mockUC)

	now := time.Now()
	expectedOutput := &usecase.RegisterOutput{
		ID:        1,
		Email:     "test@example.com",
		Username:  "testuser",
		CreatedAt: now,
	}

	input := usecase.RegisterInput{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	}
	mockUC.On("Register", mock.Anything, input).Return(expectedOutput, nil)

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.SuccessResponse
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	assert.True(t, result.Success)
	assert.Equal(t, "user registered successfully", result.Message)
	assert.NotNil(t, result.Data)
	mockUC.AssertExpectations(t)
}

func TestUserHandler_Register_InvalidBody(t *testing.T) {
	t.Parallel()

	mockUC := new(mockUserUsecase)
	app := setupUserTestApp(mockUC)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	assert.False(t, result.Success)
	assert.Equal(t, "invalid request body", result.Message)
	mockUC.AssertNotCalled(t, "Register")
}

func TestUserHandler_Register_ValidationError(t *testing.T) {
	t.Parallel()

	mockUC := new(mockUserUsecase)
	app := setupUserTestApp(mockUC)

	input := map[string]string{
		"email":    "not-an-email",
		"username": "ab",
		"password": "short",
	}
	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnprocessableEntity, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	assert.False(t, result.Success)
	assert.Equal(t, "validation failed", result.Message)
	assert.NotEmpty(t, result.Errors)
	mockUC.AssertNotCalled(t, "Register")
}

func TestUserHandler_Register_UsecaseError(t *testing.T) {
	t.Parallel()

	mockUC := new(mockUserUsecase)
	app := setupUserTestApp(mockUC)

	input := usecase.RegisterInput{
		Email:    "existing@example.com",
		Username: "testuser",
		Password: "password123",
	}
	usecaseErr := apperror.New(http.StatusBadRequest, "email already exists")
	mockUC.On("Register", mock.Anything, input).Return(nil, usecaseErr)

	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	assert.False(t, result.Success)
	assert.Equal(t, "email already exists", result.Message)
	mockUC.AssertExpectations(t)
}

func TestUserHandler_Register_EmptyBody(t *testing.T) {
	t.Parallel()

	mockUC := new(mockUserUsecase)
	app := setupUserTestApp(mockUC)

	input := map[string]string{}
	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnprocessableEntity, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var result response.ErrorResponse
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	assert.False(t, result.Success)
	assert.Equal(t, "validation failed", result.Message)
	assert.NotEmpty(t, result.Errors)
}
