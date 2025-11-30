package utils

import (
	"auth-system/internal/middleware"
	"log/slog"

	"github.com/gin-gonic/gin"
)

func SendVerificationEmail(c *gin.Context, email string, code string) {
	// Placeholder for sending email
	traceID, _ := c.Get(middleware.TraceIDKey)
	slog.Info("Sending verification email", "to", email, "code", code, "trace_id", traceID)
}

func SendPasswordResetEmail(c *gin.Context, email string, code string) {
	// Placeholder for sending email
	// The URL format should be: hostname:port/path?code=<code>
	traceID, _ := c.Get(middleware.TraceIDKey)
	slog.Info("Sending password reset email", "to", email, "code", code, "trace_id", traceID)
}
