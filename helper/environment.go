package helper

import (
	"os"
	"strconv"
	"time"
)

func GetStringEnv(key string, fallback string) string {
	value := os.Getenv(key)

	if value == "" {
		return fallback
	}

	return value
}

func GetIntEnv(key string, fallback int) int {
	value := os.Getenv(key)

	if value == "" {
		return fallback
	}

	v, _ := strconv.Atoi(value)

	return v
}

func GetDurationEnv(key string, fallback string) time.Duration {
	value := os.Getenv(key)

	if value == "" {
		value = fallback
	}

	
	t, _ := time.ParseDuration(value)

	return t
}
