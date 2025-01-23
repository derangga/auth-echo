package responder

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type Response struct {
	Data    any    `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
	HTTPStatus int `json:"http_status,omitempty"`
}

func BuildResponse(c echo.Context, response Response) error {
	return c.JSON(response.HTTPStatus, response)
}


func RespondOK(c echo.Context, data interface{}, message string) error {
	msg := message
	if msg == "" {
		msg = http.StatusText(http.StatusOK)
	}
	return BuildResponse(c, Response{
		Message:    message,
		Data:       data,
		HTTPStatus: http.StatusOK,
	})
}

func ResponseCreated(c echo.Context, message string) error {
	temp := message
	if message == "" {
		temp = http.StatusText(http.StatusCreated)
	}
	return BuildResponse(c, Response{
		Message: temp,
		HTTPStatus: http.StatusCreated,
	})
}

func ResponseBadRequest(c echo.Context, message string) error {
	temp := message
	if message == "" {
		temp = http.StatusText(http.StatusBadRequest)
	}
	return BuildResponse(c, Response{
		Message: temp,
		HTTPStatus: http.StatusBadRequest,
	})
}

func ResponseUnprocessableEntity(c echo.Context, message string) error {
	temp := message
	if message == "" {
		temp = http.StatusText(http.StatusUnprocessableEntity)
	}
	return BuildResponse(c, Response{
		Message: temp,
		HTTPStatus: http.StatusUnprocessableEntity,
	})
}

func ResponseUnauthorize(c echo.Context, message string) error {
	temp := message
	if message == "" {
		temp = http.StatusText(http.StatusUnauthorized)
	}
	return BuildResponse(c, Response{
		Message: temp,
		HTTPStatus: http.StatusUnauthorized,
	})
}
