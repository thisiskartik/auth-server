package main

import (
	"auth-system/internal/config"
	"auth-system/internal/database"
	"auth-system/internal/handlers"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1. Load Config
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Connect to Database
	if err := database.ConnectDB(cfg); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Connected to Database")

	// 3. Connect to Redis
	if err := database.ConnectRedis(cfg); err != nil {
		log.Fatalf("Failed to connect to redis: %v", err)
	}
	log.Println("Connected to Redis")

	// 4. Setup Handlers
	h := handlers.NewHandler(cfg)

	// 5. Setup Router
	r := gin.Default()

	// Base Path
	basePath := fmt.Sprintf("/api/%s/authorization-server", cfg.APIVersion)
	api := r.Group(basePath)
	{
		api.POST("/register", h.Register)
		api.POST("/login", h.Login)
		api.POST("/oauth/token", h.OAuthToken)
		api.POST("/oauth/refresh", h.OAuthRefresh)
		api.GET("/client/me", h.ClientMe)
		api.GET("/user/me", h.UserMe)
	}

	// 6. Start Server
	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Server starting on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
