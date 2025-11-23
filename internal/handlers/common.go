package handlers

import (
	"auth-system/internal/config"
	"auth-system/internal/database"
	"auth-system/internal/middleware"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
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
	Error     string         `json:"error"`
	Fields    map[string]any `json:"fields,omitempty"`
	Code      int            `json:"code,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
}

func (h *Handler) RespondError(c *gin.Context, status int, err error, message string) {
	traceID, _ := c.Get(middleware.TraceIDKey)
	
	// Log client errors as Warn/Info
	slog.Warn("Client Error", 
		"status", status, 
		"message", message, 
		"error", err,
		"trace_id", traceID,
	)
	c.JSON(status, ErrorResponse{
		Error: message,
	})
}

func (h *Handler) RespondValidationError(c *gin.Context, fields map[string]any) {
	traceID, _ := c.Get(middleware.TraceIDKey)
	
	slog.Warn("Validation Error",
		"fields", fields,
		"trace_id", traceID,
	)
	
	c.JSON(http.StatusBadRequest, ErrorResponse{
		Error:   "Validation Failed",
		Fields:  fields,
	})
}

func (h *Handler) RespondInternalError(c *gin.Context, err error, code int) {
	// Get Trace ID from Middleware
	val, exists := c.Get(middleware.TraceIDKey)
	traceID := ""
	if exists {
		traceID = val.(string)
	} else {
		// Fallback
		traceID = uuid.New().String()
	}

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

func msgForValidationTag(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email"
	case "oneof":
		return "Should be one of [" + strings.ReplaceAll(fe.Param(), " ", ", ") + "]"
	case "min":
		return "Should be at least " + fe.Param() + " characters long"
	}
	return "Invalid value"
}

// GetValidationErrors binds the JSON and returns validation errors or fatal error.
func (h *Handler) GetValidationErrors(c *gin.Context, obj any) (map[string]any, error) {
	if err := c.ShouldBindJSON(obj); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			out := make(map[string]any)
			for _, fe := range ve {
				fieldName := fe.Field()
				// Use reflection to get the JSON tag from the struct
				if field, ok := reflect.TypeOf(obj).Elem().FieldByName(fe.StructField()); ok {
					if tag := field.Tag.Get("json"); tag != "" {
						fieldName = strings.Split(tag, ",")[0]
					}
				}
				out[fieldName] = msgForValidationTag(fe)
			}
			return out, nil
		}
		// JSON Parsing Error (Syntax)
		return nil, err
	}
	return nil, nil
}

// BindJSONWithValidation attempts to bind the request body to the given struct.
// If binding fails due to validation errors, it returns true (handled) and sends a Validation Error response.
// If binding fails due to JSON syntax errors, it returns true (handled) and sends a Bad Request response.
// If binding succeeds, it returns false, and the caller should proceed.
func (h *Handler) BindJSONWithValidation(c *gin.Context, obj any) bool {
	validationErrors, err := h.GetValidationErrors(c, obj)
	if err != nil {
		h.RespondError(c, http.StatusBadRequest, err, "Invalid JSON")
		return true
	}
	if len(validationErrors) > 0 {
		h.RespondValidationError(c, validationErrors)
		return true
	}
	return false
}

func MergeErrors(dest, src map[string]any) {
	for k, v := range src {
		if existing, ok := dest[k]; ok {
			// If collision, create list or append
			var list []string

			// Handle existing value
			switch val := existing.(type) {
			case string:
				list = append(list, val)
			case []string:
				list = append(list, val...)
			}

			// Handle new value
			switch val := v.(type) {
			case string:
				list = append(list, val)
			case []string:
				list = append(list, val...)
			}

			dest[k] = list
		} else {
			dest[k] = v
		}
	}
}
