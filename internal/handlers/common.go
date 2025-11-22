package handlers

import (
	"auth-system/internal/config"
	"auth-system/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

// Error Codes
const (
	ErrDatabase = 100
	ErrRedis    = 101
	ErrCrypto   = 102
	ErrToken    = 103
	ErrJSON     = 104
	ErrGeneric  = 105
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
	Error     string `json:"error"`
	Code      int    `json:"code,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
}

func (h *Handler) RespondError(c *gin.Context, status int, err error, message string) {
	c.JSON(status, ErrorResponse{
		Error: message,
	})
}

func (h *Handler) RespondInternalError(c *gin.Context, err error, code int) {
	// Generate unique trace ID
	traceID := uuid.New().String()
	
	// In a real app, log the error, traceID, and file info
	// _, file, line, _ := runtime.Caller(1)
	// log.Printf("TraceID: %s, Error: %v, File: %s:%d", traceID, err, file, line)
	
	c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error:   "Internal Server Error",
		Code:    code,
		TraceID: traceID,
	})
}
