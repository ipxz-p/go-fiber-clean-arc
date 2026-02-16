package usecase

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/entity"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/mocks"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newTestJWTManager() *token.JWTManager {
	return token.NewJWTManager("test-access-secret", "test-refresh-secret", 15, 7)
}

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}


func TestLogin_Success(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	hashedPw := hashPassword(t, "correct-password")
	user := &entity.User{
		ID:       1,
		Email:    "test@example.com",
		Username: "testuser",
		Password: hashedPw,
	}

	mockUserRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockTokenRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).Return(nil)

	input := LoginInput{
		Email:    "test@example.com",
		Password: "correct-password",
	}

	output, err := uc.Login(context.Background(), input)

	require.NoError(t, err)
	assert.NotEmpty(t, output.AccessToken)
	assert.NotEmpty(t, output.RefreshToken)
	assert.False(t, output.AccessTokenExpiresAt.IsZero())
	assert.False(t, output.RefreshTokenExpiresAt.IsZero())
	mockUserRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

func TestLogin_TrimsEmail(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	hashedPw := hashPassword(t, "password")
	user := &entity.User{ID: 1, Email: "test@example.com", Username: "testuser", Password: hashedPw}

	mockUserRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockTokenRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).Return(nil)

	input := LoginInput{
		Email:    "  test@example.com  ",
		Password: "password",
	}

	output, err := uc.Login(context.Background(), input)

	require.NoError(t, err)
	assert.NotEmpty(t, output.AccessToken)
	mockUserRepo.AssertExpectations(t)
}

func TestLogin_UserNotFound(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	mockUserRepo.On("GetByEmail", mock.Anything, "unknown@example.com").Return(nil, nil)

	input := LoginInput{
		Email:    "unknown@example.com",
		Password: "password",
	}

	output, err := uc.Login(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
	assert.Equal(t, "invalid email or password", appErr.Message)
	mockUserRepo.AssertExpectations(t)
}

func TestLogin_WrongPassword(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	hashedPw := hashPassword(t, "correct-password")
	user := &entity.User{ID: 1, Email: "test@example.com", Password: hashedPw}

	mockUserRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)

	input := LoginInput{
		Email:    "test@example.com",
		Password: "wrong-password",
	}

	output, err := uc.Login(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
	assert.Equal(t, "invalid email or password", appErr.Message)
}

func TestLogin_GetByEmailError(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	dbErr := apperror.New(http.StatusInternalServerError, "db error")
	mockUserRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, dbErr)

	input := LoginInput{
		Email:    "test@example.com",
		Password: "password",
	}

	output, err := uc.Login(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
	mockUserRepo.AssertExpectations(t)
}

func TestLogin_TokenStoreError(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	hashedPw := hashPassword(t, "password")
	user := &entity.User{ID: 1, Email: "test@example.com", Username: "testuser", Password: hashedPw}

	mockUserRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)
	storeErr := apperror.New(http.StatusInternalServerError, "failed to store refresh token")
	mockTokenRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).Return(storeErr)

	input := LoginInput{
		Email:    "test@example.com",
		Password: "password",
	}

	output, err := uc.Login(context.Background(), input)

	assert.Nil(t, output)
	assert.Error(t, err)
}


func TestLogout_Success(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	refreshTokenStr, jti, expiresAt, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	storedToken := &entity.RefreshToken{
		ID:        1,
		UserID:    1,
		Token:     jti,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
	mockTokenRepo.On("GetByToken", mock.Anything, jti).Return(storedToken, nil)
	mockTokenRepo.On("RevokeByToken", mock.Anything, jti).Return(nil)

	err = uc.Logout(context.Background(), refreshTokenStr)

	assert.NoError(t, err)
	mockTokenRepo.AssertExpectations(t)
}

func TestLogout_EmptyToken(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	err := uc.Logout(context.Background(), "")

	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusBadRequest, appErr.Code)
	assert.Equal(t, "refresh token is required", appErr.Message)
}

func TestLogout_InvalidToken(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	err := uc.Logout(context.Background(), "invalid-jwt-token")

	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusBadRequest, appErr.Code)
	assert.Equal(t, "invalid refresh token", appErr.Message)
}

func TestLogout_TokenNotFoundInDB(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	refreshTokenStr, jti, _, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	mockTokenRepo.On("GetByToken", mock.Anything, jti).Return(nil, nil)

	err = uc.Logout(context.Background(), refreshTokenStr)

	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusBadRequest, appErr.Code)
	assert.Equal(t, "invalid refresh token", appErr.Message)
}

func TestLogout_GetByTokenError(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	refreshTokenStr, jti, _, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	dbErr := apperror.New(http.StatusInternalServerError, "db error")
	mockTokenRepo.On("GetByToken", mock.Anything, jti).Return(nil, dbErr)

	err = uc.Logout(context.Background(), refreshTokenStr)

	assert.Error(t, err)
	mockTokenRepo.AssertExpectations(t)
}


func TestRefreshToken_Success(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	refreshTokenStr, jti, expiresAt, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	storedToken := &entity.RefreshToken{
		ID:        1,
		UserID:    1,
		Token:     jti,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
	mockTokenRepo.On("GetByToken", mock.Anything, jti).Return(storedToken, nil)

	output, err := uc.RefreshToken(context.Background(), refreshTokenStr)

	require.NoError(t, err)
	assert.NotEmpty(t, output.AccessToken)
	assert.False(t, output.AccessTokenExpiresAt.IsZero())
	assert.Empty(t, output.RefreshToken)
	mockTokenRepo.AssertExpectations(t)
}

func TestRefreshToken_EmptyToken(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	output, err := uc.RefreshToken(context.Background(), "")

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
	assert.Equal(t, "refresh token is required", appErr.Message)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	output, err := uc.RefreshToken(context.Background(), "invalid-jwt-token")

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
	assert.Equal(t, "invalid or expired refresh token", appErr.Message)
}

func TestRefreshToken_TokenNotFoundInDB(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	refreshTokenStr, jti, _, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	mockTokenRepo.On("GetByToken", mock.Anything, jti).Return(nil, nil)

	output, err := uc.RefreshToken(context.Background(), refreshTokenStr)

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
	assert.Equal(t, "invalid refresh token", appErr.Message)
}

func TestRefreshToken_Revoked(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	refreshTokenStr, jti, expiresAt, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	storedToken := &entity.RefreshToken{
		ID:        1,
		UserID:    1,
		Token:     jti,
		ExpiresAt: expiresAt,
		Revoked:   true,
	}
	mockTokenRepo.On("GetByToken", mock.Anything, jti).Return(storedToken, nil)

	output, err := uc.RefreshToken(context.Background(), refreshTokenStr)

	assert.Nil(t, output)
	assert.Error(t, err)
	var appErr *apperror.AppError
	assert.True(t, errors.As(err, &appErr))
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
	assert.Equal(t, "refresh token has been revoked", appErr.Message)
}

func TestRefreshToken_GetByTokenError(t *testing.T) {
	t.Parallel()

	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)
	jwtMgr := newTestJWTManager()
	uc := NewAuthUsecase(mockUserRepo, mockTokenRepo, jwtMgr)

	refreshTokenStr, jti, _, err := jwtMgr.GenerateRefreshToken(1, "test@example.com", "testuser")
	require.NoError(t, err)

	dbErr := apperror.New(http.StatusInternalServerError, "db error")
	mockTokenRepo.On("GetByToken", mock.Anything, jti).Return(nil, dbErr)

	output, err := uc.RefreshToken(context.Background(), refreshTokenStr)

	assert.Nil(t, output)
	assert.Error(t, err)
	mockTokenRepo.AssertExpectations(t)
}
