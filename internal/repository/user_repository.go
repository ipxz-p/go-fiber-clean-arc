package repository

import (
	"context"
	"errors"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/entity"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"
	"net/http"
	"gorm.io/gorm"
)

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	GetByID(ctx context.Context, id int64) (*entity.User, error)
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
	GetByUsername(ctx context.Context, username string) (*entity.User, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *entity.User) error {
	result := r.db.WithContext(ctx).Create(user)
	if result.Error != nil {
		return apperror.Wrap(result.Error, http.StatusInternalServerError, "failed to create user")
	}
	return nil
}

func (r *userRepository) GetByID(ctx context.Context, id int64) (*entity.User, error) {
	var user entity.User
	result := r.db.WithContext(ctx).First(&user, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, apperror.Wrap(result.Error, http.StatusInternalServerError, "failed to get user by id")
	}
	return &user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	var user entity.User
	result := r.db.WithContext(ctx).Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, apperror.Wrap(result.Error, http.StatusInternalServerError, "failed to get user by email")
	}
	return &user, nil
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	var user entity.User
	result := r.db.WithContext(ctx).Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, apperror.Wrap(result.Error, http.StatusInternalServerError, "failed to get user by username")
	}
	return &user, nil
}
