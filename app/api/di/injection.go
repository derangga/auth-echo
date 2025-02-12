package di

import (
	"auth-echo/database/connection"
	"auth-echo/handler"
	"auth-echo/repository"
	"auth-echo/server"
	"auth-echo/server/config"
	"auth-echo/server/middleware"
	"auth-echo/usecase"

	"github.com/go-playground/validator/v10"
	"github.com/jmoiron/sqlx"
)

func provideDB(config config.DatabaseConfig) *sqlx.DB {
	return connection.NewPostgresDatabase(config)
}

func provideJWTAuth(config *config.AuthConfig) *middleware.JWTAuth {
	return middleware.ProvideJWTAuth(config.JWTSecret)
}

func provideUserRepository(db *sqlx.DB) repository.UserRepository {
	return repository.NewUserRepository(db)
}

func provideSessionRepository(db *sqlx.DB) repository.SessionRepository {
	return repository.NewSessionRepository(db)
}

func provideAuthUsecase(
	config config.AuthConfig,
	userRepository repository.UserRepository,
	sessionRepository repository.SessionRepository,
) usecase.AuthUsecase {
	return usecase.NewAuthUsecase(config, userRepository, sessionRepository)
}

func provideAuthHandler(
	authUC usecase.AuthUsecase,
	validator *validator.Validate,
) handler.AuthHandler {
	return handler.NewAuthHandler(
		authUC, validator,
	)
}

func provideHealthzHandler() handler.HealthzHandler {
	return handler.NewHealthz()
}

func provideHandlers(
	authHandler handler.AuthHandler,
	healthzHandler handler.HealthzHandler,
) handler.Handlers {
	return handler.NewHandlers(authHandler, healthzHandler)
}

func provideValidator() *validator.Validate {
	return validator.New()
}

func provideHttpServer(
	config *config.Config,
	handlers handler.Handlers,
	jwtAuth *middleware.JWTAuth,
) server.HttpServer {
	return server.NewHttpServer(
		config,
		handlers,
		jwtAuth,
	)
}

func InitHttpServer(config *config.Config) server.HttpServer {
	database := provideDB(config.DatabaseConfig)
	validator := provideValidator()
	jwtAuth := provideJWTAuth(&config.AuthConfig)
	userRepository := provideUserRepository(database)
	sessionRepository := provideSessionRepository(database)
	authUC := provideAuthUsecase(config.AuthConfig, userRepository, sessionRepository)
	authHandler := provideAuthHandler(authUC, validator)
	healthzHandler := provideHealthzHandler()
	handlers := provideHandlers(authHandler, healthzHandler)
	server := provideHttpServer(config, handlers, jwtAuth)

	return server
}
