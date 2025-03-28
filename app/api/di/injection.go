package di

import (
	"auth-echo/handler"
	connection "auth-echo/lib/database"
	redisclient "auth-echo/lib/redis_client"
	"auth-echo/repository"
	"auth-echo/server"
	"auth-echo/server/config"
	"auth-echo/server/middleware"
	"auth-echo/usecase"

	"github.com/go-playground/validator/v10"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
)

func provideDB(config config.DatabaseConfig) *sqlx.DB {
	return connection.NewPostgresDatabase(config)
}

func provideRedisClient(config config.RedisConfig) *redis.Client {
	return redisclient.NewRedisClient(config)
}

func provideJWTAuth(config *config.AuthConfig, redisClient *redis.Client) *middleware.JWTAuth {
	return middleware.ProvideJWTAuth(config.JWTSecret, redisClient)
}

func provideUserRepository(db *sqlx.DB) repository.UserRepository {
	return repository.NewUserRepository(db)
}

func provideSessionRepository(db *sqlx.DB) repository.SessionRepository {
	return repository.NewSessionRepository(db)
}

func provideLoginDeviceRepository(db *sqlx.DB) repository.LoginDevicesRepository {
	return repository.NewLoginDeviceRepository(db)
}

func provideAuthUsecase(
	config config.AuthConfig,
	redisClient *redis.Client,
	userRepository repository.UserRepository,
	sessionRepository repository.SessionRepository,
	loginDeviceRepository repository.LoginDevicesRepository,
) usecase.AuthUsecase {
	return usecase.NewAuthUsecase(
		config,
		redisClient,
		userRepository,
		sessionRepository,
		loginDeviceRepository,
	)
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
	redisClient := provideRedisClient(config.RedisConfig)
	validator := provideValidator()
	jwtAuth := provideJWTAuth(&config.AuthConfig, redisClient)
	userRepository := provideUserRepository(database)
	sessionRepository := provideSessionRepository(database)
	loginDeviceRepository := provideLoginDeviceRepository(database)
	authUC := provideAuthUsecase(
		config.AuthConfig,
		redisClient,
		userRepository,
		sessionRepository,
		loginDeviceRepository,
	)
	authHandler := provideAuthHandler(authUC, validator)
	healthzHandler := provideHealthzHandler()
	handlers := provideHandlers(authHandler, healthzHandler)
	server := provideHttpServer(config, handlers, jwtAuth)

	return server
}
