package handler

import (
	appctx "auth-echo/lib/app_context"
	customerror "auth-echo/lib/custom_error"
	"auth-echo/lib/responder"
	"auth-echo/model/dto"
	"auth-echo/model/requests"
	"auth-echo/model/serializer"
	"auth-echo/usecase"
	"net"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

type AuthHandler struct {
	authUC    usecase.AuthUsecase
	validator *validator.Validate
}

func NewAuthHandler(
	authUC usecase.AuthUsecase,
	validator *validator.Validate,
) AuthHandler {
	return AuthHandler{
		authUC:    authUC,
		validator: validator,
	}
}

func (h AuthHandler) Login(c echo.Context) error {
	// bind request to struct
	var req requests.Login
	err := c.Bind(&req)
	if err != nil {
		log.Errorf("AuthHandler.bind: %w", err)
		return responder.ResponseBadRequest(c, "")
	}

	deviceId := c.Request().Header.Get("X-Device-ID")
	if deviceId == "" {
		return responder.ResponseBadRequest(c, "Unknown Device Identity")
	}

	err = h.validator.Struct(req)
	if err != nil {
		log.Errorf("AuthHandler.validateStruct: %w", err)
		return responder.ResponseBadRequest(c, "")
	}

	userAgent := c.Request().UserAgent()
	ipAddress, _, err := net.SplitHostPort(c.Request().RemoteAddr)
	if err != nil {
		log.Errorf("AuthHandler.getIpAddr: %w", err)
		return responder.ResponseBadRequest(c, "")
	}
	loginDTO := dto.Login{
		Username:       req.Username,
		Password:       req.Password,
		DeviceIdentity: deviceId,
		UserAgent:      userAgent,
		IPAddress:      net.IP(ipAddress),
	}

	// proceed to usecase
	authorization, err := h.authUC.Login(c.Request().Context(), loginDTO)
	if err != nil {
		return responder.ResponseUnprocessableEntity(c, err.Error())
	}

	return responder.RespondOK(c, serializer.PublicAuthorization(authorization), "")
}

func (h AuthHandler) Register(c echo.Context) error {
	var req requests.Register
	err := c.Bind(&req)
	if err != nil {
		return responder.ResponseBadRequest(c, "")
	}

	// validate body request
	err = h.validator.Struct(req)
	if err != nil {
		return responder.ResponseBadRequest(c, "register membutuhkan name, username, email, password")
	}

	err = h.authUC.Register(c.Request().Context(), req)
	if err != nil {
		if ce, ok := err.(customerror.CustomError); ok {
			return responder.ResponseUnprocessableEntity(c, ce.Error())
		}
		return responder.ResponseUnprocessableEntity(c, err.Error())
	}

	return responder.ResponseCreated(c, "user successfuly register")
}

func (h AuthHandler) RenewalToken(c echo.Context) error {
	headerReq, err := appctx.GetRefreshTokenMeta(c.Request().Context())
	if err != nil {
		return responder.ResponseUnauthorize(c, "")
	}

	var req requests.RefreshTokenBodyReq
	err = c.Bind(&req)
	if err != nil {
		return responder.ResponseBadRequest(c, "")
	}

	authorization, err := h.authUC.RenewalToken(c.Request().Context(), headerReq, req)
	if err != nil {
		if ce, ok := err.(customerror.CustomError); ok {
			return responder.BuildResponse(c, responder.Response{
				Message:    ce.Error(),
				HTTPStatus: ce.HTTPCode,
			})
		}
		return responder.ResponseUnprocessableEntity(c, "")
	}

	return responder.RespondOK(c, serializer.PublicAuthorization(authorization), "")
}

func (h AuthHandler) Logout(c echo.Context) error {
	userMeta, err := appctx.GetUserClaims(c.Request().Context())
	if err != nil {
		return responder.ResponseUnauthorize(c, "")
	}

	uid, err := userMeta.GetSubject()
	if err != nil {
		return responder.ResponseBadRequest(c, "")
	}
	userId, _ := strconv.Atoi(uid)

	err = h.authUC.Logout(c.Request().Context(), userMeta.DeviceId, userId)
	if err != nil {
		return responder.ResponseUnprocessableEntity(c, "")
	}

	return responder.RespondOK(c, nil, "Success logout")
}
