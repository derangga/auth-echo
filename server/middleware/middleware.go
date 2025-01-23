package middleware

import (
	"auth-echo/server/config"

	"github.com/labstack/echo/v4"
	middleware "github.com/labstack/echo/v4/middleware"
)

func SetupGlobalMiddleware(e *echo.Echo, config config.ApplicationConfig) {
	e.Use(middleware.ContextTimeoutWithConfig(middleware.ContextTimeoutConfig{Skipper: middleware.DefaultSkipper, Timeout: config.Timeout}))
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
}