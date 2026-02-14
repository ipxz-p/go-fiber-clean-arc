package validator

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

type Validator struct {
	validate *validator.Validate
}

func New() *Validator {
	return &Validator{
		validate: validator.New(),
	}
}

func (v *Validator) Validate(i interface{}) map[string]string {
	err := v.validate.Struct(i)
	if err == nil {
		return nil
	}

	errs := make(map[string]string)
	for _, e := range err.(validator.ValidationErrors) {
		field := strings.ToLower(e.Field())
		errs[field] = msgForTag(e)
	}
	return errs
}

func msgForTag(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", strings.ToLower(fe.Field()))
	case "email":
		return "must be a valid email address"
	case "min":
		return fmt.Sprintf("must be at least %s characters", fe.Param())
	case "max":
		return fmt.Sprintf("must be at most %s characters", fe.Param())
	case "alphanum":
		return "must contain only alphanumeric characters"
	default:
		return fmt.Sprintf("failed on '%s' validation", fe.Tag())
	}
}
