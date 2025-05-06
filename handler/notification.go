package handler

import (
	appctx "auth-echo/lib/app_context"
	"auth-echo/lib/responder"
	"auth-echo/model/requests"
	"auth-echo/usecase"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

type NotificationHandler struct {
	notificationUC usecase.NotificationUsecase
	validator      *validator.Validate
}

func NewNotificationHandler(
	notificationUC usecase.NotificationUsecase,
	validator *validator.Validate,
) NotificationHandler {
	return NotificationHandler{notificationUC: notificationUC, validator: validator}
}

func (h NotificationHandler) RegisterFcmDevice(c echo.Context) error {
	userMeta, err := appctx.GetUserClaims(c.Request().Context())
	if err != nil {
		return responder.ResponseUnauthorize(c, "")
	}
	userId, err := userMeta.GetUserID()
	if err != nil {
		return responder.ResponseUnauthorize(c, "")
	}

	var req requests.FcmDevice
	err = c.Bind(&req)
	if err != nil {
		return responder.ResponseBadRequest(c, "")
	}

	err = h.validator.Struct(req)
	if err != nil {
		log.Errorf("NotificationHandler.validateStruct: %w", err)
		return responder.ResponseBadRequest(c, "")
	}

	req.UserID = userId
	req.DeviceIdentity = userMeta.DeviceId

	err = h.notificationUC.RegisterFcmDevice(c.Request().Context(), req)
	if err != nil {
		return responder.ResponseUnprocessableEntity(c, "")
	}

	return responder.RespondOK(c, "device registered", "")
}

func (h NotificationHandler) SendNotification(c echo.Context) error {
	userMeta, err := appctx.GetUserClaims(c.Request().Context())
	if err != nil {
		return responder.ResponseUnauthorize(c, "")
	}
	userId, err := userMeta.GetUserID()
	if err != nil {
		return responder.ResponseUnauthorize(c, "")
	}

	var req requests.Notification

	if err := c.Bind(&req); err != nil {
		return responder.ResponseBadRequest(c, "")
	}

	if err := h.validator.Struct(req); err != nil {
		log.Errorf("NotificationHandler.validateStruct: %w", err)
		return responder.ResponseBadRequest(c, "")
	}

	req.UserID = userId
	err = h.notificationUC.SendNotification(c.Request().Context(), req)

	if err != nil {
		return responder.ResponseUnprocessableEntity(c, "")
	}

	return responder.RespondOK(c, "notification send", "")
}
