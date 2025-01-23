package customerror

import (
	"errors"
	"net/http"
)

type CustomError struct {
	Code string
	HTTPCode int
	Err      error
}

func (c CustomError) Error() string {
	if c.Err != nil {
		return c.Err.Error()
	}

	return ""
}

func BuildErrorReference(httpCode int, err error) error {
	return CustomError{
		HTTPCode: httpCode, 
		Err: err,
	}
}

func BuildError(httpCode int, message string) error {
	msg := message
	if message == "" {
		msg = http.StatusText(httpCode)
	}
	return CustomError{
		HTTPCode: httpCode, 
		Err: errors.New(msg),
	}
}

func BuildErrorReferenceWithCode(code string, httpCode int, err error) error {
	return CustomError{
		Code: code,
		HTTPCode: httpCode,
		Err: err,
	}
}