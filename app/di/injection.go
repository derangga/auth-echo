package di

import (
	"auth-echo/handler"
	connection "auth-echo/lib/database"
	"auth-echo/lib/firebase"
	"auth-echo/lib/rabbitmq"
	redisclient "auth-echo/lib/redis_client"
	"auth-echo/repository"
	"auth-echo/server"
	"auth-echo/server/config"
	"auth-echo/server/middleware"
	"auth-echo/usecase"
	"context"
	"fmt"
	"log"

	"firebase.google.com/go/v4/messaging"
	"github.com/go-playground/validator/v10"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

func provideFcmDeviceRepository(db *sqlx.DB) repository.FcmDeviceRepository {
	return repository.NewFcmDeviceRepository(db)
}

func provideNotificationRepository(db *sqlx.DB) repository.NotificationRepository {
	return repository.NewNotificationRepository(db)
}

func provideFirebaseClient(ctx context.Context) *messaging.Client {
	client, err := firebase.NewFirebaseClient(ctx)
	if err != nil {
		log.Fatalf("failed create firebase client %w", err)
	}
	fcm, err := client.Messaging(ctx)
	if err != nil {
		log.Fatalf("failed create firebase client %w", err)
	}

	return fcm
}

func providePrometheusHistogram(config config.ApplicationConfig) *prometheus.HistogramVec {
	return promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    config.Service,
		Help:    fmt.Sprintf("Histogram of %s request duration.", config.Service),
		Buckets: prometheus.LinearBuckets(1, 1, 10), // Adjust bucket sizes as needed
	}, []string{"path", "method", "status"})
}

func provideAuthUsecase(
	config config.AuthConfig,
	redisClient *redis.Client,
	rabbitMqCh rabbitmq.RabbitMQChannel,
	userRepository repository.UserRepository,
	sessionRepository repository.SessionRepository,
) usecase.AuthUsecase {
	return usecase.NewAuthUsecase(
		config,
		redisClient,
		rabbitMqCh,
		userRepository,
		sessionRepository,
	)
}

func provideNotificationUsecase(
	fcm *messaging.Client,
	fcmDeviceRepo repository.FcmDeviceRepository,
	notificationRepo repository.NotificationRepository,
) usecase.NotificationUsecase {
	return usecase.NewNotificationUsecase(
		fcm,
		fcmDeviceRepo,
		notificationRepo,
	)
}

func provideAuthLoggerUsecase(
	loginDeviceRepo repository.LoginDevicesRepository,
) usecase.AuthLoggerUsecase {
	return usecase.NewAuthLoggerUsecase(loginDeviceRepo)
}

func provideAuthHandler(
	authUC usecase.AuthUsecase,
	validator *validator.Validate,
) handler.AuthHandler {
	return handler.NewAuthHandler(
		authUC, validator,
	)
}

func provideNotificationHandler(
	notificationUC usecase.NotificationUsecase,
	validator *validator.Validate,
) handler.NotificationHandler {
	return handler.NewNotificationHandler(notificationUC, validator)
}

func provideHealthzHandler() handler.HealthzHandler {
	return handler.NewHealthz()
}

func provideHandlers(
	authHandler handler.AuthHandler,
	notificationHandler handler.NotificationHandler,
	healthzHandler handler.HealthzHandler,
) handler.Handlers {
	return handler.NewHandlers(authHandler, notificationHandler, healthzHandler)
}

func provideValidator() *validator.Validate {
	return validator.New()
}

func provideHttpServer(
	config *config.Config,
	handlers handler.Handlers,
	jwtAuth *middleware.JWTAuth,
	promHistogram *prometheus.HistogramVec,
) server.HttpServer {
	return server.NewHttpServer(
		config,
		handlers,
		jwtAuth,
		promHistogram,
	)
}

func InitHttpServer(ctx context.Context, config *config.Config, rabbitMqCh rabbitmq.RabbitMQChannel) server.HttpServer {
	database := provideDB(config.DatabaseConfig)
	fcmClient := provideFirebaseClient(ctx)
	redisClient := provideRedisClient(config.RedisConfig)
	validator := provideValidator()
	prometheus := providePrometheusHistogram(config.ApplicationConfig)
	jwtAuth := provideJWTAuth(&config.AuthConfig, redisClient)
	userRepository := provideUserRepository(database)
	sessionRepository := provideSessionRepository(database)
	fcmDeviceRepository := provideFcmDeviceRepository(database)
	notificationRepository := provideNotificationRepository(database)
	notificationUC := provideNotificationUsecase(fcmClient, fcmDeviceRepository, notificationRepository)

	authUC := provideAuthUsecase(
		config.AuthConfig,
		redisClient,
		rabbitMqCh,
		userRepository,
		sessionRepository,
	)
	authHandler := provideAuthHandler(authUC, validator)
	notificationHandler := provideNotificationHandler(notificationUC, validator)
	healthzHandler := provideHealthzHandler()
	handlers := provideHandlers(authHandler, notificationHandler, healthzHandler)
	server := provideHttpServer(config, handlers, jwtAuth, prometheus)

	return server
}

func InitConsumer(ctx context.Context, config *config.Config) server.Consumer {
	database := provideDB(config.DatabaseConfig)
	fcmClient := provideFirebaseClient(ctx)
	fcmDeviceRepository := provideFcmDeviceRepository(database)
	notificationRepository := provideNotificationRepository(database)
	loginDeviceRepository := provideLoginDeviceRepository(database)
	notificationUC := provideNotificationUsecase(fcmClient, fcmDeviceRepository, notificationRepository)
	authLoggerUC := provideAuthLoggerUsecase(loginDeviceRepository)

	return server.NewConsumer(authLoggerUC, notificationUC)
}
