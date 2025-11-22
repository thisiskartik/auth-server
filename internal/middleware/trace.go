package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const TraceIDKey = "trace_id"

func TraceIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		traceID := uuid.New().String()
		c.Set(TraceIDKey, traceID)
		
		// Add Trace ID to response header
		c.Header("X-Trace-ID", traceID)

		c.Next()
	}
}

func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		method := c.Request.Method
		
		traceID, _ := c.Get(TraceIDKey)

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		slog.Info("Request",
			"status", status,
			"method", method,
			"path", path,
			"query", raw,
			"latency", latency,
			"trace_id", traceID,
		)
	}
}
