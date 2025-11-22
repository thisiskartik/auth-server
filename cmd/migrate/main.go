package main

import (
	"auth-system/internal/config"
	"auth-system/internal/database"
	"auth-system/internal/models"
	"log"
)

func main() {
	// 1. Load Config
	cfg, err := config.LoadConfig(false)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Connect to Database
	if err := database.ConnectDB(cfg); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Connected to Database")

	// 3. Migrate
	log.Println("Starting migration...")
	err = database.DB.AutoMigrate(&models.User{}, &models.Client{})
	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
	log.Println("Migration completed successfully.")
}
