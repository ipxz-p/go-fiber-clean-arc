package usecase

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/entity"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/repository"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"

	"golang.org/x/crypto/bcrypt"
)

// RegisterInput represents the data required to register a new user.
type RegisterInput struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Username string `json:"username" validate:"required,min=3,max=100,alphanum"`
	Password string `json:"password" validate:"required,min=8,max=72"`
}

// RegisterOutput represents the response after a successful registration.
type RegisterOutput struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

// UserUsecase defines the contract for user business logic.
type UserUsecase interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterOutput, error)
}

// userUsecase implements UserUsecase.
type userUsecase struct {
	userRepo repository.UserRepository
}

// NewUserUsecase creates a new UserUsecase.
func NewUserUsecase(userRepo repository.UserRepository) UserUsecase {
	return &userUsecase{userRepo: userRepo}
}

func (uc *userUsecase) Register(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	input.Email = strings.TrimSpace(input.Email)
	input.Username = strings.TrimSpace(input.Username)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, apperror.New(http.StatusInternalServerError, "failed to hash password")
	}

	exists, err := uc.userRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, err
	}
	if exists != nil {
		return nil, apperror.New(http.StatusBadRequest, "email already exists")
	}
	exists, err = uc.userRepo.GetByUsername(ctx, input.Username)
	if err != nil {
		return nil, err
	}
	if exists != nil {
		return nil, apperror.New(http.StatusBadRequest, "username already exists")
	}

	user := &entity.User{
		Email:    input.Email,
		Username: input.Username,
		Password: string(hashedPassword),
	}

	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return &RegisterOutput{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
	}, nil
}
