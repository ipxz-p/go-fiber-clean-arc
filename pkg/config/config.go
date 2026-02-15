package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AppPort    string
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	JWTAccessSecret        string
	JWTRefreshSecret       string
	JWTAccessExpiryMinutes int
	JWTRefreshExpiryDays   int

	SentryDSN string
}

func Load() (*Config, error) {
	godotenv.Load()

	config := &Config{
		AppPort:    getEnv("APP_PORT", "3000"),
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", "postgres"),
		DBName:     getEnv("DB_NAME", "go_fiber_db"),

		JWTAccessSecret:        getEnv("JWT_ACCESS_SECRET", ""),
		JWTRefreshSecret:       getEnv("JWT_REFRESH_SECRET", ""),
		JWTAccessExpiryMinutes: getEnvInt("JWT_ACCESS_EXPIRY_MINUTES", 15),
		JWTRefreshExpiryDays:   getEnvInt("JWT_REFRESH_EXPIRY_DAYS", 7),

		SentryDSN: getEnv("SENTRY_DSN", ""),
	}

	if config.DBHost == "" || config.DBName == "" {
		return nil, fmt.Errorf("DB_HOST and DB_NAME are required")
	}

	if config.JWTAccessSecret == "" || config.JWTRefreshSecret == "" {
		return nil, fmt.Errorf("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are required")
	}

	return config, nil
}

// DSN returns the PostgreSQL connection string for GORM.
func (c *Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.DBHost, c.DBPort, c.DBUser, c.DBPassword, c.DBName,
	)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}
