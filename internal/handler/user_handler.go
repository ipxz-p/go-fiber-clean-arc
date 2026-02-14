package handler

import (
	"github.com/ipxz-p/go-fiber-clean-arc/internal/usecase"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/response"
	"github.com/ipxz-p/go-fiber-clean-arc/pkg/validator"

	"github.com/gofiber/fiber/v2"
)

type UserHandler struct {
	userUsecase usecase.UserUsecase
	validator   *validator.Validator
}

func NewUserHandler(userUsecase usecase.UserUsecase, validator *validator.Validator) *UserHandler {
	return &UserHandler{
		userUsecase: userUsecase,
		validator:   validator,
	}
}

func (h *UserHandler) Register(c *fiber.Ctx) error {
	var input usecase.RegisterInput

	if err := c.BodyParser(&input); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "invalid request body")
	}

	if errs := h.validator.Validate(input); errs != nil {
		return response.ValidationError(c, "validation failed", errs)
	}

	output, err := h.userUsecase.Register(c.UserContext(), input)
	if err != nil {
		return err
	}

	return response.Success(c, fiber.StatusCreated, "user registered successfully", output)
}