package handlers

import (
	"auth-system/internal/config"
	"auth-system/internal/database"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
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
	// Log client errors as Warn/Info
	slog.Warn("Client Error", "status", status, "message", message, "error", err)
	c.JSON(status, ErrorResponse{
		Error: message,
	})
}

func (h *Handler) RespondInternalError(c *gin.Context, err error, code int) {
	// Generate unique trace ID
	traceID := uuid.New().String()

	// Log the full error details
	slog.Error("Internal Server Error",
		"trace_id", traceID,
		"code", code,
		"error", err,
		"path", c.Request.URL.Path,
		"method", c.Request.Method,
	)

	c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error:   "Internal Server Error",
		Code:    code,
		TraceID: traceID,
	})
}
