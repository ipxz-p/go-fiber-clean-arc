package repository

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/entity"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"

	"gorm.io/gorm"
)

type TokenRepository interface {
	Create(ctx context.Context, token *entity.RefreshToken) error
	GetByToken(ctx context.Context, token string) (*entity.RefreshToken, error)
	RevokeByToken(ctx context.Context, token string) error
	RevokeAllByUserID(ctx context.Context, userID int64) error
	DeleteExpired(ctx context.Context) error
}

type tokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) TokenRepository {
	return &tokenRepository{db: db}
}

func (r *tokenRepository) Create(ctx context.Context, token *entity.RefreshToken) error {
	result := r.db.WithContext(ctx).Create(token)
	if result.Error != nil {
		return apperror.New(http.StatusInternalServerError, "failed to store refresh token")
	}
	return nil
}

func (r *tokenRepository) GetByToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	var refreshToken entity.RefreshToken
	result := r.db.WithContext(ctx).Where("token = ?", token).First(&refreshToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, apperror.New(http.StatusInternalServerError, "failed to get refresh token")
	}
	return &refreshToken, nil
}

func (r *tokenRepository) RevokeByToken(ctx context.Context, token string) error {
	result := r.db.WithContext(ctx).
		Model(&entity.RefreshToken{}).
		Where("token = ?", token).
		Update("revoked", true)
	if result.Error != nil {
		return apperror.New(http.StatusInternalServerError, "failed to revoke refresh token")
	}
	return nil
}

func (r *tokenRepository) RevokeAllByUserID(ctx context.Context, userID int64) error {
	result := r.db.WithContext(ctx).
		Model(&entity.RefreshToken{}).
		Where("user_id = ? AND revoked = false", userID).
		Update("revoked", true)
	if result.Error != nil {
		return apperror.New(http.StatusInternalServerError, "failed to revoke refresh tokens")
	}
	return nil
}

func (r *tokenRepository) DeleteExpired(ctx context.Context) error {
	result := r.db.WithContext(ctx).
		Where("expires_at < ? OR revoked = true", time.Now()).
		Delete(&entity.RefreshToken{})
	if result.Error != nil {
		return apperror.New(http.StatusInternalServerError, "failed to delete expired tokens")
	}
	return nil
}
