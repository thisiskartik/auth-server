package handlers

import (
	"auth-system/internal/config"
	"auth-system/internal/database"
	"runtime"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

type Handler struct {
	DB          *gorm.DB
	RedisClient *redis.Client
	Config      *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{
		DB:          database.DB,
		RedisClient: database.RedisClient,
		Config:      cfg,
	}
}

type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func (h *Handler) RespondError(c *gin.Context, status int, err error, message string) {
	code := ""
	if status >= 500 {
		// Generate unique error code
		_, file, line, _ := runtime.Caller(1)
		code = uuid.New().String()
		// In a real app, we would log this code with the error and stack trace
		// log.Printf("Error %s: %v in %s:%d", code, err, file, line)
		_ = file
		_ = line
	}
	c.JSON(status, ErrorResponse{
		Error: message,
		Code:  code,
	})
}
