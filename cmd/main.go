package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/handler"
	mw "github.com/ipxz-p/go-fiber-clean-arc/internal/middleware"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/repository"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/usecase"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/config"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/database"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/token"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/validator"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	db, err := database.NewDatabase(cfg.DSN())
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to database")

	jwtManager := token.NewJWTManager(cfg.JWTAccessSecret, cfg.JWTRefreshSecret, cfg.JWTAccessExpiryMinutes, cfg.JWTRefreshExpiryDays)

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)

	userUsecase := usecase.NewUserUsecase(userRepo)
	authUsecase := usecase.NewAuthUsecase(userRepo, tokenRepo, jwtManager)

	validate := validator.New()
	userHandler := handler.NewUserHandler(userUsecase, validate)
	authHandler := handler.NewAuthHandler(authUsecase, validate)

	app := fiber.New(fiber.Config{
		ErrorHandler: mw.ErrorHandler,
		AppName:      "Go Fiber Clean Arc API v1.0.0",
	})

	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:5173",
		AllowCredentials: true,
	}))
	app.Use(mw.RequestLogger())

	api := app.Group("/api/v1")

	auth := api.Group("/auth")
	auth.Post("/register", userHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Post("/refresh", authHandler.RefreshToken)

	auth.Post("/logout", mw.JWTAuth(jwtManager), authHandler.Logout)

	addr := fmt.Sprintf(":%s", cfg.AppPort)
	slog.Info("server starting", "port", cfg.AppPort)
	if err := app.Listen(addr); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
