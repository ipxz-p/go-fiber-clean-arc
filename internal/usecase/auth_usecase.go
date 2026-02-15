package usecase

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/entity"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/repository"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/token"

	"golang.org/x/crypto/bcrypt"
)

type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type TokenOutput struct {
	AccessToken  string 
	AccessTokenExpiresAt time.Time   
	RefreshToken string   
	RefreshTokenExpiresAt time.Time 
}

type AuthUsecase interface {
	Login(ctx context.Context, input LoginInput) (*TokenOutput, error)
	Logout(ctx context.Context, refreshToken string) error
	RefreshToken(ctx context.Context, refreshToken string) (*TokenOutput, error)
}

type authUsecase struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	jwt       *token.JWTManager
}

func NewAuthUsecase(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	jwt *token.JWTManager,
) AuthUsecase {
	return &authUsecase{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		jwt:       jwt,
	}
}

func (uc *authUsecase) Login(ctx context.Context, input LoginInput) (*TokenOutput, error) {
	input.Email = strings.TrimSpace(input.Email)

	user, err := uc.userRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, apperror.New(http.StatusUnauthorized, "invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return nil, apperror.New(http.StatusUnauthorized, "invalid email or password")
	}

	return uc.generateTokenPair(ctx, user)
}

func (uc *authUsecase) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return apperror.New(http.StatusBadRequest, "refresh token is required")
	}

	claims, err := uc.jwt.ValidateRefreshToken(refreshToken)
	if err != nil {
		return apperror.New(http.StatusBadRequest, "invalid refresh token")
	}

	stored, err := uc.tokenRepo.GetByToken(ctx, claims.ID)
	if err != nil {
		return err
	}
	if stored == nil {
		return apperror.New(http.StatusBadRequest, "invalid refresh token")
	}

	return uc.tokenRepo.RevokeByToken(ctx, claims.ID)
}

func (uc *authUsecase) RefreshToken(ctx context.Context, refreshToken string) (*TokenOutput, error) {
	if refreshToken == "" {
		return nil, apperror.New(http.StatusUnauthorized, "refresh token is required")
	}

	claims, err := uc.jwt.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, apperror.New(http.StatusUnauthorized, "invalid or expired refresh token")
	}

	stored, err := uc.tokenRepo.GetByToken(ctx, claims.ID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, apperror.New(http.StatusUnauthorized, "invalid refresh token")
	}

	if stored.Revoked {
		return nil, apperror.New(http.StatusUnauthorized, "refresh token has been revoked")
	}

	accessToken, expiresAt, err := uc.jwt.GenerateAccessToken(claims.UserID, claims.Email, claims.Username)
	if err != nil {
		return nil, apperror.New(http.StatusInternalServerError, "failed to generate access token")
	}

	return &TokenOutput{
		AccessToken: accessToken,
		AccessTokenExpiresAt: expiresAt,
	}, nil
}

func (uc *authUsecase) generateTokenPair(ctx context.Context, user *entity.User) (*TokenOutput, error) {
	accessToken, expiresAt, err := uc.jwt.GenerateAccessToken(user.ID, user.Email, user.Username)
	if err != nil {
		return nil, apperror.New(http.StatusInternalServerError, "failed to generate access token")
	}

	refreshTokenStr, jti, refreshExpiresAt, err := uc.jwt.GenerateRefreshToken(user.ID, user.Email, user.Username)
	if err != nil {
		return nil, apperror.New(http.StatusInternalServerError, "failed to generate refresh token")
	}

	refreshTokenEntity := &entity.RefreshToken{
		UserID:    user.ID,
		Token:     jti,
		ExpiresAt: refreshExpiresAt,
	}
	if err := uc.tokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		return nil, err
	}

	return &TokenOutput{
		AccessToken:  accessToken,
		AccessTokenExpiresAt: expiresAt,
		RefreshToken: refreshTokenStr,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}
