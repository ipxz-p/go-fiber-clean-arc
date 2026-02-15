package di

import (
	"github.com/ipxz-p/go-fiber-clean-arc/internal/handler"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/repository"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/usecase"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/config"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/token"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/validator"

	"gorm.io/gorm"
)

type Container struct {
	UserHandler *handler.UserHandler
	AuthHandler *handler.AuthHandler
	JWTManager  *token.JWTManager
}

func NewContainer(db *gorm.DB, cfg *config.Config) *Container {
	jwtManager := token.NewJWTManager(
		cfg.JWTAccessSecret,
		cfg.JWTRefreshSecret,
		cfg.JWTAccessExpiryMinutes,
		cfg.JWTRefreshExpiryDays,
	)

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)

	userUsecase := usecase.NewUserUsecase(userRepo)
	authUsecase := usecase.NewAuthUsecase(userRepo, tokenRepo, jwtManager)

	validate := validator.New()
	userHandler := handler.NewUserHandler(userUsecase, validate)
	authHandler := handler.NewAuthHandler(authUsecase, validate)

	return &Container{
		UserHandler: userHandler,
		AuthHandler: authHandler,
		JWTManager:  jwtManager,
	}
}
