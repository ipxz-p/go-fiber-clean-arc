package response

import "github.com/gofiber/fiber/v2"

type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

type ErrorResponse struct {
	Success bool              `json:"success"`
	Message string            `json:"message"`
	Errors  map[string]string `json:"errors,omitempty"`
}

func Success(c *fiber.Ctx, statusCode int, message string, data interface{}) error {
	return c.Status(statusCode).JSON(SuccessResponse{
		Success: true,
		Data:    data,
		Message: message,
	})
}

func Error(c *fiber.Ctx, statusCode int, message string) error {
	return c.Status(statusCode).JSON(ErrorResponse{
		Success: false,
		Message: message,
	})
}

func ValidationError(c *fiber.Ctx, message string, errors map[string]string) error {
	return c.Status(fiber.StatusUnprocessableEntity).JSON(ErrorResponse{
		Success: false,
		Message: message,
		Errors:  errors,
	})
}
