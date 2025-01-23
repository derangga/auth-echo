package handler

import (
	appctx "auth-echo/lib/app_context"
	"auth-echo/lib/responder"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

type HealthzHandler struct {

}

func NewHealthz() HealthzHandler {
	return HealthzHandler{}
}

func (h HealthzHandler) Healthz(c echo.Context) error {
	// testing authorization
	claims, err := appctx.GetUserClaims(c.Request().Context())
	if err != nil {
		log.Errorf("error: %w", err)
		responder.ResponseBadRequest(c, "")
	}
	sub, err := claims.GetSubject()
	if err != nil {
		log.Errorf("error: %w", err)
		responder.ResponseBadRequest(c, "")
	}
	return responder.RespondOK(c, sub, "")
}