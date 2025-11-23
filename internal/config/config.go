package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DBUser          string
	DBPassword      string
	DBName          string
	DBHost          string
	DBPort          string
	RedisAddr       string
	RedisPassword   string
	ServerHost      string
	ServerPort      string
	JWTSecret       string
	AccessTokenExp  int
	RefreshTokenExp int
	AuthCodeExp     int
	APIVersion      string
	EncryptionKey   string
}

func LoadConfig(strict bool) (*Config, error) {
	_ = godotenv.Load() // Ignore error if .env file not found

	var err error
	cfg := &Config{}

	cfg.DBUser, err = getEnv("POSTGRES_USER")
	if err != nil { return nil, err }

	cfg.DBPassword, err = getEnv("POSTGRES_PASSWORD")
	if err != nil { return nil, err }

	cfg.DBName, err = getEnv("POSTGRES_DB")
	if err != nil { return nil, err }

	cfg.DBHost, err = getEnv("DB_HOST")
	if err != nil { return nil, err }

	cfg.DBPort, err = getEnv("DB_PORT")
	if err != nil { return nil, err }

	// Helper for conditional strictness
	getEnvOrSkip := func(key string) (string, error) {
		val, err := getEnv(key)
		if err != nil {
			if strict {
				return "", err
			}
			return "", nil
		}
		return val, nil
	}

	cfg.RedisAddr, err = getEnvOrSkip("REDIS_ADDR")
	if err != nil { return nil, err }

	// Optional
	cfg.RedisPassword, _ = getEnv("REDIS_PASSWORD")

	cfg.ServerHost, err = getEnvOrSkip("SERVER_HOST")
	if err != nil { return nil, err }
	if cfg.ServerHost == "" {
		cfg.ServerHost = "localhost" // Default
	}

	cfg.ServerPort, err = getEnvOrSkip("SERVER_PORT")
	if err != nil { return nil, err }

	cfg.JWTSecret, err = getEnvOrSkip("JWT_SECRET")
	if err != nil { return nil, err }

	accessTokenStr, err := getEnvOrSkip("ACCESS_TOKEN_EXP_MINUTES")
	if err != nil { return nil, err }
	if accessTokenStr != "" {
		cfg.AccessTokenExp, err = strconv.Atoi(accessTokenStr)
		if err != nil { return nil, fmt.Errorf("ACCESS_TOKEN_EXP_MINUTES must be an integer") }
	}

	refreshTokenStr, err := getEnvOrSkip("REFRESH_TOKEN_EXP_DAYS")
	if err != nil { return nil, err }
	if refreshTokenStr != "" {
		cfg.RefreshTokenExp, err = strconv.Atoi(refreshTokenStr)
		if err != nil { return nil, fmt.Errorf("REFRESH_TOKEN_EXP_DAYS must be an integer") }
	}

	authCodeStr, err := getEnvOrSkip("AUTH_CODE_EXP_MINUTES")
	if err != nil { return nil, err }
	if authCodeStr != "" {
		cfg.AuthCodeExp, err = strconv.Atoi(authCodeStr)
		if err != nil { return nil, fmt.Errorf("AUTH_CODE_EXP_MINUTES must be an integer") }
	}

	cfg.APIVersion, err = getEnvOrSkip("API_VERSION")
	if err != nil { return nil, err }

	cfg.EncryptionKey, err = getEnvOrSkip("ENCRYPTION_KEY")
	if err != nil { return nil, err }

	return cfg, nil
}

func getEnv(key string) (string, error) {
	if value, ok := os.LookupEnv(key); ok {
		return value, nil
	}
	return "", fmt.Errorf("environment variable %s is required", key)
}
