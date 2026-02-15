package apperror

import pkgerrors "github.com/pkg/errors"

type AppError struct {
	Code    int
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func New(code int, message string) error {
	return pkgerrors.WithStack(&AppError{Code: code, Message: message})
}

// Wrap wraps an existing error with AppError and captures stack trace.
func Wrap(err error, code int, message string) error {
	if err == nil {
		return nil
	}
	return pkgerrors.WithStack(&AppError{Code: code, Message: message, Err: err})
}
