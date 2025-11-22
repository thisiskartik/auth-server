package config

import (
	"os"
	"strconv"
	"github.com/joho/godotenv"
)

type Config struct {
	DBUser            string
	DBPassword        string
	DBName            string
	DBHost            string
	DBPort            string
	RedisAddr         string
	RedisPassword     string
	ServerPort        string
	JWTSecret         string
	AccessTokenExp    int
	RefreshTokenExp   int
	AuthCodeExp       int
	APIVersion        string
	EncryptionKey     string
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load() // Ignore error if .env file not found

	accessTokenExp, _ := strconv.Atoi(getEnv("ACCESS_TOKEN_EXP_MINUTES", "15"))
	refreshTokenExp, _ := strconv.Atoi(getEnv("REFRESH_TOKEN_EXP_DAYS", "7"))
	authCodeExp, _ := strconv.Atoi(getEnv("AUTH_CODE_EXP_MINUTES", "5"))

	return &Config{
		DBUser:          getEnv("POSTGRES_USER", "postgres"),
		DBPassword:      getEnv("POSTGRES_PASSWORD", "postgres"),
		DBName:          getEnv("POSTGRES_DB", "auth_db"),
		DBHost:          getEnv("DB_HOST", "localhost"),
		DBPort:          getEnv("DB_PORT", "5432"),
		RedisAddr:       getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:   getEnv("REDIS_PASSWORD", ""),
		ServerPort:      getEnv("SERVER_PORT", "8080"),
		JWTSecret:       getEnv("JWT_SECRET", "supersecretkey"),
		AccessTokenExp:  accessTokenExp,
		RefreshTokenExp: refreshTokenExp,
		AuthCodeExp:     authCodeExp,
		APIVersion:      getEnv("API_VERSION", "v1"),
		EncryptionKey:   getEnv("ENCRYPTION_KEY", "thisis32bitlongpassphraseimusing"), // Must be 32 bytes for AES-256
	}, nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
