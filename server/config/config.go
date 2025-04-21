package config

import (
	"auth-echo/helper"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var (
	once   sync.Once
	config *Config
)

type ApplicationConfig struct {
	Host    string
	Port    string
	Service string
	Timeout time.Duration
}

type DatabaseConfig struct {
	Name         string
	Port         string
	Host         string
	Username     string
	Password     string
	MaxOpenConns int
	MaxIdleConns int
	MaxLifetime  time.Duration
}

type RedisConfig struct {
	Host         string
	Port         string
	Passsword    string
	Username     string
	DB           int
	MaxRetries   int
	PoolSize     int
	MinIdleCons  int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// AuthConfig holds the configuration for auth
type AuthConfig struct {
	JWTSecret          string
	RefreshTokenSecret string
	JWTValidDuration   time.Duration
	RefreshDuration    time.Duration
	BcryptSalt         int
}

type Config struct {
	ApplicationConfig ApplicationConfig
	DatabaseConfig    DatabaseConfig
	RedisConfig       RedisConfig
	AuthConfig        AuthConfig
}

func BuildConfig() *Config {
	once.Do(func() {
		config = &Config{}

		godotenv.Load(".env")

		config.ApplicationConfig = ApplicationConfig{
			Host:    helper.GetStringEnv("SERVICE_HOST", "127.0.0.1"),
			Port:    helper.GetStringEnv("SERVICE_PORT", "8080"),
			Service: helper.GetStringEnv("SERVICE_NAME", "echouser"),
			Timeout: helper.GetDurationEnv("SERVICE_TIMEOUT", "30000ms"),
		}

		config.DatabaseConfig = DatabaseConfig{
			Name:         helper.GetStringEnv("POSTGRES_DB", "127.0.0.1"),
			Port:         helper.GetStringEnv("POSTGRES_DB_PORT", "5432"),
			Host:         helper.GetStringEnv("POSTGRES_DB_HOST", ""),
			Username:     helper.GetStringEnv("POSTGRES_USER", ""),
			Password:     helper.GetStringEnv("POSTGRES_PASSWORD", ""),
			MaxOpenConns: helper.GetIntEnv("POSTGRES_DB_MAX_OPEN_CONNECTION", 5),
			MaxIdleConns: helper.GetIntEnv("POSTGRES_DB_MAX_IDLE_CONNECTION", 5),
			MaxLifetime:  helper.GetDurationEnv("POSTGRES_DB_MAX_LIFETIME", "30m"),
		}

		config.RedisConfig = RedisConfig{
			Host:         helper.GetStringEnv("REDIS_HOST", "127.0.0.1"),
			Port:         helper.GetStringEnv("REDIS_PORT", "6379"),
			Username:     helper.GetStringEnv("REDIS_USERNAME", ""),
			Passsword:    helper.GetStringEnv("REDIS_PASSWORD", ""),
			DB:           helper.GetIntEnv("REDIS_DB", 0),
			MaxRetries:   helper.GetIntEnv("REDIS_MAX_RETRIES", 0),
			PoolSize:     helper.GetIntEnv("REDIS_POOL_SIZE", 5),
			MinIdleCons:  helper.GetIntEnv("REDIS_MIN_IDLE_CONNS", 1),
			DialTimeout:  helper.GetDurationEnv("REDIS_DIAL_TIMEOUT", ""),
			ReadTimeout:  helper.GetDurationEnv("REDIS_READ_TIMEOUT", ""),
			WriteTimeout: helper.GetDurationEnv("REDIS_WRITE_TIMEOUT", ""),
		}

		config.AuthConfig = AuthConfig{
			JWTSecret:          helper.GetStringEnv("JWT_SECRET", ""),
			JWTValidDuration:   helper.GetDurationEnv("JWT_VALID_DURATION", ""),
			RefreshTokenSecret: helper.GetStringEnv("REFRESH_TOKEN_SECRET", ""),
			RefreshDuration:    helper.GetDurationEnv("REFRESH_VALID_DURATION", ""),
			BcryptSalt:         helper.GetIntEnv("BCRYPT_SALT", 0),
		}
	})

	return config
}
