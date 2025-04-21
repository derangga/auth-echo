package server

import (
	"auth-echo/handler"
	"auth-echo/routes"
	"auth-echo/server/config"
	"auth-echo/server/middleware"
	"context"
	"fmt"
	"log"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
)

type HttpServer interface {
	ListenAndServe() error
	Stop()
}

type Server struct {
	echo          *echo.Echo
	config        *config.Config
	handler       handler.Handlers
	jwtAuth       *middleware.JWTAuth
	promHistogram *prometheus.HistogramVec
}

func NewHttpServer(
	config *config.Config,
	handler handler.Handlers,
	jwtAuth *middleware.JWTAuth,
	promHistogram *prometheus.HistogramVec,
) HttpServer {
	e := echo.New()
	middleware.SetupGlobalMiddleware(e, config.ApplicationConfig)

	srv := &Server{
		echo:          e,
		config:        config,
		handler:       handler,
		jwtAuth:       jwtAuth,
		promHistogram: promHistogram,
	}

	srv.connectCoreWithEcho()
	return srv
}

func (s *Server) ListenAndServe() error {
	serviceUrl := fmt.Sprintf("%s:%s", s.config.ApplicationConfig.Host, s.config.ApplicationConfig.Port)
	return s.echo.Start(serviceUrl)
}

func (s *Server) Stop() {
	e := s.echo
	err := e.Server.Shutdown(context.Background())
	if err != nil {
		log.Fatal("failed to open shutdown service:", err.Error())
	}
}

func (s *Server) connectCoreWithEcho() {
	appRoutes := routes.NewRoutes(s.echo, s.handler, s.jwtAuth, s.promHistogram)
	appRoutes.RegisterRoute()
}
