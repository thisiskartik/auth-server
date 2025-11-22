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
	ServerPort      string
	JWTSecret       string
	AccessTokenExp  int
	RefreshTokenExp int
	AuthCodeExp     int
	APIVersion      string
	EncryptionKey   string
}

func LoadConfig() (*Config, error) {
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

	cfg.RedisAddr, err = getEnv("REDIS_ADDR")
	if err != nil { return nil, err }

	// Optional
	cfg.RedisPassword, _ = getEnv("REDIS_PASSWORD")

	cfg.ServerPort, err = getEnv("SERVER_PORT")
	if err != nil { return nil, err }

	cfg.JWTSecret, err = getEnv("JWT_SECRET")
	if err != nil { return nil, err }

	accessTokenStr, err := getEnv("ACCESS_TOKEN_EXP_MINUTES")
	if err != nil { return nil, err }
	cfg.AccessTokenExp, _ = strconv.Atoi(accessTokenStr)

	refreshTokenStr, err := getEnv("REFRESH_TOKEN_EXP_DAYS")
	if err != nil { return nil, err }
	cfg.RefreshTokenExp, _ = strconv.Atoi(refreshTokenStr)

	authCodeStr, err := getEnv("AUTH_CODE_EXP_MINUTES")
	if err != nil { return nil, err }
	cfg.AuthCodeExp, _ = strconv.Atoi(authCodeStr)

	cfg.APIVersion, err = getEnv("API_VERSION")
	if err != nil { return nil, err }

	cfg.EncryptionKey, err = getEnv("ENCRYPTION_KEY")
	if err != nil { return nil, err }

	return cfg, nil
}

func getEnv(key string) (string, error) {
	if value, ok := os.LookupEnv(key); ok {
		return value, nil
	}
	return "", fmt.Errorf("environment variable %s is required", key)
}
