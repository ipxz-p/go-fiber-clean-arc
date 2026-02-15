package middleware

import (
	"errors"
	"log/slog"

	sentryfiber "github.com/getsentry/sentry-go/fiber"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/apperror"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/response"

	"github.com/gofiber/fiber/v2"
)

func ErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "internal server error"

	var appErr *apperror.AppError
	if errors.As(err, &appErr) {
		code = appErr.Code
		message = appErr.Message
	} else if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	slog.Error("request error",
		"method", c.Method(),
		"path", c.Path(),
		"status", code,
		"error", err,
	)

	if code >= fiber.StatusInternalServerError {
		if hub := sentryfiber.GetHubFromContext(c); hub != nil {
			hub.CaptureException(err)
		}
	}

	return response.Error(c, code, message)
}
