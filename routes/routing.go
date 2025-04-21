package routes

import (
	"auth-echo/handler"
	"auth-echo/server/middleware"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type AppRoutes struct {
	echo          *echo.Echo
	handler       handler.Handlers
	jwtAuth       *middleware.JWTAuth
	promHistogram *prometheus.HistogramVec
}

func NewRoutes(
	echo *echo.Echo,
	handler handler.Handlers,
	jwtAuth *middleware.JWTAuth,
	promHistogram *prometheus.HistogramVec,
) AppRoutes {
	return AppRoutes{
		echo:          echo,
		handler:       handler,
		jwtAuth:       jwtAuth,
		promHistogram: promHistogram,
	}
}

func (r AppRoutes) RegisterRoute() {
	h := r.handler
	userMid := r.jwtAuth.UserMiddleware()
	reAuthMid := r.jwtAuth.ReAuthMiddleware()

	r.registerRoute(r.echo, http.MethodGet, "/metrics", echo.WrapHandler(promhttp.Handler()))

	authGroup := r.echo.Group("/auth")
	r.registerGroupRoute(authGroup, http.MethodPost, "/login", h.AuthHandler.Login)
	r.registerGroupRoute(authGroup, http.MethodPost, "/register", h.AuthHandler.Register)
	r.registerGroupRoute(authGroup, http.MethodPost, "/logout", h.AuthHandler.Logout, userMid)
	r.registerGroupRoute(authGroup, http.MethodPost, "/refresh", h.AuthHandler.RenewalToken, reAuthMid)

	r.registerRoute(r.echo, http.MethodGet, "/healtz", h.HealthzHandler.Healthz, userMid)
}

func (r AppRoutes) registerGroupRoute(g *echo.Group, method string, path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) {
	g.Add(method, path, r.wrapHandlerWithMetrics(path, method, h), m...)
}

func (r AppRoutes) registerRoute(e *echo.Echo, method string, path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) {
	e.Add(method, path, r.wrapHandlerWithMetrics(path, method, h), m...)
}

func (r AppRoutes) wrapHandlerWithMetrics(
	path string,
	method string,
	handler echo.HandlerFunc,
) echo.HandlerFunc {
	return func(c echo.Context) error {
		startTime := time.Now()

		// Execute the actual handler and catch any errors
		err := handler(c)

		// Regardless of whether an error occurred, record the metrics
		duration := time.Since(startTime).Seconds()

		r.promHistogram.WithLabelValues(path, method, strconv.Itoa(c.Response().Status)).Observe(duration)

		return err
	}
}
