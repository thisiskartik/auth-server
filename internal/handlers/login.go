package handlers

import (
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	ClientID      string `json:"client_id" binding:"required"`
	CodeChallenge string `json:"code_challenge" binding:"required"`
	Email         string `json:"email" binding:"required"`
	Password      string `json:"password" binding:"required"`
}

type AuthCodeData struct {
	ClientID      string `json:"client_id"`
	UserID        string `json:"user_id"`
	ExpiresAt     int64  `json:"expires_at"`
	CodeChallenge string `json:"code_challenge"`
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if h.BindJSONWithValidation(c, &req) {
		return
	}

	// 1. Validate Client
	var client models.Client
	// Assuming ClientID passed is the UUID ID.
	if err := h.DB.Where("id = ?", req.ClientID).First(&client).Error; err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid Client ID")
		return
	}

	// 2. Validate User
	var user models.User
	if err := h.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid credentials")
		return
	}

	if !utils.CheckPassword(req.Password, user.Password) {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid credentials")
		return
	}

	// 3. Generate Authorization Code
	code, err := utils.GenerateRandomString(16)
	if err != nil {
		h.RespondInternalError(c, err, 2001)
		return
	}

	expiresAt := time.Now().Add(time.Duration(h.Config.AuthCodeExp) * time.Minute).Unix()

	data := AuthCodeData{
		ClientID:      req.ClientID,
		UserID:        user.ID.String(),
		ExpiresAt:     expiresAt,
		CodeChallenge: req.CodeChallenge,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		h.RespondInternalError(c, err, 2002)
		return
	}

	// Store in Redis
	err = h.RedisClient.Set(context.Background(), code, jsonData, time.Duration(h.Config.AuthCodeExp)*time.Minute).Err()
	if err != nil {
		h.RespondInternalError(c, err, 2003)
		return
	}

	slog.Info("User logged in", "user_id", user.ID, "client_id", client.ID)
	c.JSON(http.StatusOK, gin.H{"code": code})
}
