package main

import (
	"auth-system/internal/config"
	"auth-system/internal/database"
	"auth-system/internal/handlers"
	"auth-system/internal/middleware"
	"fmt"
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	// 0. Setup Logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// 1. Load Config
	cfg, err := config.LoadConfig(true)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// 2. Connect to Database
	if err := database.ConnectDB(cfg); err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to Database")

	// 3. Connect to Redis
	if err := database.ConnectRedis(cfg); err != nil {
		slog.Error("Failed to connect to redis", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to Redis")

	// 4. Setup Handlers
	h := handlers.NewHandler(cfg)

	// 5. Setup Router
	r := gin.New() // Use New() to avoid default middleware
	r.Use(gin.Recovery())
	r.Use(middleware.TraceIDMiddleware())
	r.Use(middleware.LoggerMiddleware())

	// Base Path
	basePath := fmt.Sprintf("/api/%s/authorization-server", cfg.APIVersion)
	api := r.Group(basePath)
	{
		api.POST("/user/register", h.RegisterUser)
		api.POST("/client/register", h.RegisterClient)
		api.POST("/login", h.Login)
		api.POST("/logout", h.Logout)
		api.POST("/oauth/token", h.OAuthToken)
		api.POST("/oauth/refresh", h.OAuthRefresh)
		api.GET("/client/me", h.ClientMe)
		api.GET("/user/me", h.UserMe)
		api.POST("/user/verify", h.VerifyEmail)
		api.POST("/user/verify/resend", h.ResendVerificationCode)
		api.POST("/user/password/forgot", h.ForgotPassword)
		api.POST("/user/password/reset", h.ResetPassword)
	}

	// 6. Start Server
	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	slog.Info("Server starting", "address", addr)
	if err := r.Run(addr); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
