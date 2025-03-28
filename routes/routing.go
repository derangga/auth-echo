package routes

import (
	"auth-echo/handler"
	"auth-echo/server/middleware"
	"net/http"

	"github.com/labstack/echo/v4"
)

func RegisterRoute(
	e *echo.Echo,
	h handler.Handlers,
	jwtAuth *middleware.JWTAuth,
) {
	userMid := jwtAuth.UserMiddleware()
	reAuthMid := jwtAuth.ReAuthMiddleware()

	authGroup := e.Group("/auth")
	registerGroupRoute(authGroup, http.MethodPost, "/login", h.AuthHandler.Login)
	registerGroupRoute(authGroup, http.MethodPost, "/register", h.AuthHandler.Register)
	registerGroupRoute(authGroup, http.MethodPost, "/logout", h.AuthHandler.Logout, userMid)
	registerGroupRoute(authGroup, http.MethodPost, "/refresh", h.AuthHandler.RenewalToken, reAuthMid)

	registerRoute(e, http.MethodGet, "/healtz", h.HealthzHandler.Healthz, userMid)
}

func registerGroupRoute(g *echo.Group, method string, path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) {
	g.Add(method, path, func(c echo.Context) error {
		err := h(c)
		return err
	}, m...)
}

func registerRoute(e *echo.Echo, method string, path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) {
	e.Add(method, path, func(c echo.Context) error {
		err := h(c)
		return err
	}, m...)
}
