package database

import (
	"context"
	"auth-system/internal/config"
	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

func ConnectRedis(cfg *config.Config) error {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       0,
	})

	_, err := RedisClient.Ping(context.Background()).Result()
	return err
}
