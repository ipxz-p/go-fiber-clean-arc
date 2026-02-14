package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/ipxz-p/go-fiber-clean-arc/internal/entity"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/handler"
	mw "github.com/ipxz-p/go-fiber-clean-arc/internal/middleware"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/repository"
	"github.com/ipxz-p/go-fiber-clean-arc/internal/usecase"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/config"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/database"
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

	db, err := database.NewPostgresDB(cfg.DSN())
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to PostgreSQL")

	userRepo := repository.NewUserRepository(db)
	userUsecase := usecase.NewUserUsecase(userRepo)
	validate := validator.New()
	userHandler := handler.NewUserHandler(userUsecase, validate)

	app := fiber.New(fiber.Config{
		ErrorHandler: mw.ErrorHandler,
		AppName:      "Go Fiber Clean Arc API v1.0.0",
	})

	app.Use(recover.New())
	app.Use(cors.New())
	app.Use(mw.RequestLogger())

	api := app.Group("/api/v1")
	auth := api.Group("/auth")
	auth.Post("/register", userHandler.Register)

	addr := fmt.Sprintf(":%s", cfg.AppPort)
	slog.Info("server starting", "port", cfg.AppPort)
	if err := app.Listen(addr); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
