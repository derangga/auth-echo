package server

import (
	"auth-echo/handler"
	"auth-echo/routes"
	"auth-echo/server/config"
	"auth-echo/server/middleware"
	"context"
	"log"

	"github.com/labstack/echo/v4"
)

type HttpServer interface {
	ListenAndServe() error
	Stop()
}

type Server struct {
	echo    *echo.Echo
	config  *config.Config
	handler handler.Handlers
	jwtAuth *middleware.JWTAuth
}

func NewHttpServer(
	config *config.Config,
	handler handler.Handlers,
	jwtAuth *middleware.JWTAuth,
) HttpServer {
	e := echo.New()
	middleware.SetupGlobalMiddleware(e, config.ApplicationConfig)

	srv := &Server{
		echo:    e,
		config:  config,
		handler: handler,
		jwtAuth: jwtAuth,
	}

	srv.connectCoreWithEcho()
	return srv
}

func (s *Server) ListenAndServe() error {
	return s.echo.Start("127.0.0.1:" + s.config.ApplicationConfig.Port)
}

func (s *Server) Stop() {
	e := s.echo
	err := e.Server.Shutdown(context.Background())
	if err != nil {
		log.Fatal("failed to open shutdown service:", err.Error())
	}
}

func (s *Server) connectCoreWithEcho() {
	routes.RegisterRoute(s.echo, s.handler, s.jwtAuth)
}
