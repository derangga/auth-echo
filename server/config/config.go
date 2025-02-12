package config

import (
	"auth-echo/helper"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var (
	once sync.Once
	config  *Config
)

type ApplicationConfig struct {
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

// AuthConfig holds the configuration for auth
type AuthConfig struct {
	JWTSecret        string 
	RefreshTokenSecret string
	JWTValidDuration time.Duration
	RefreshDuration time.Duration
	BcryptSalt       int
}

type Config struct {
	ApplicationConfig ApplicationConfig
	DatabaseConfig DatabaseConfig
	AuthConfig AuthConfig
}

func BuildConfig() *Config {
	once.Do(func() {
		config = &Config{}

		godotenv.Load(".env")

		config.ApplicationConfig = ApplicationConfig{
			Port: helper.GetStringEnv("SERVICE_PORT", "8080"),
			Service: helper.GetStringEnv("SERVICE_NAME", "echouser"),
			Timeout: helper.GetDurationEnv("SERVICE_TIMEOUT", "30000ms"),
		}

		config.DatabaseConfig = DatabaseConfig{
			Name: helper.GetStringEnv("DB_NAME", ""),
			Port: helper.GetStringEnv("DB_PORT", ""),
			Host: helper.GetStringEnv("DB_HOST", ""),
			Username: helper.GetStringEnv("DB_USERNAME", ""),
			Password: helper.GetStringEnv("DB_PASSWORD", ""),
			MaxOpenConns: helper.GetIntEnv("DB_MAX_CONNECTION", 5),
			MaxIdleConns: helper.GetIntEnv("DB_MAX_IDLE_CONNECTION", 5),
			MaxLifetime: helper.GetDurationEnv("DB_MAX_LIFETIME", "30m"),
		}
		
		config.AuthConfig = AuthConfig{
			JWTSecret: helper.GetStringEnv("JWT_SECRET", ""),
			JWTValidDuration: helper.GetDurationEnv("JWT_VALID_DURATION", ""),
			RefreshTokenSecret: helper.GetStringEnv("REFRESH_TOKEN_SECRET", ""),
			RefreshDuration: helper.GetDurationEnv("REFRESH_VALID_DURATION", ""),
			BcryptSalt: helper.GetIntEnv("BCRYPT_SALT", 0),
		}
	})

	return config
}