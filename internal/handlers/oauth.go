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

type TokenRequest struct {
	Code         string `json:"code" binding:"required"`
	CodeVerifier string `json:"code_verifier" binding:"required"` // Optional in strict prompt, but needed for PKCE
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *Handler) OAuthToken(c *gin.Context) {
	// 1. Authenticate Client
	client, ok := h.authenticateClient(c)
	if !ok {
		return
	}

	// 2. Read Request
	var req TokenRequest
	if h.BindJSONWithValidation(c, &req) {
		return
	}

	// 3. Check Redis for Code & Delete immediately (Atomic)
	val, err := h.RedisClient.GetDel(context.Background(), req.Code).Result()
	if err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid or expired code")
		return
	}

	var data AuthCodeData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		h.RespondInternalError(c, err, 3002)
		return
	}

	// Verify Code belongs to Client
	if data.ClientID != client.ID.String() {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid code for this client")
		return
	}

	// Check expiry (Redis handles TTL but double check logic)
	if time.Now().Unix() > data.ExpiresAt {
		h.RespondError(c, http.StatusUnauthorized, nil, "Code expired")
		return
	}

	// Verify PKCE if verifier provided OR if challenge exists
	// If challenge exists in Redis, verifier MUST be provided
	if data.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			h.RespondError(c, http.StatusBadRequest, nil, "code_verifier required")
			return
		}
		if !utils.VerifyCodeChallenge(data.CodeChallenge, req.CodeVerifier) {
			h.RespondError(c, http.StatusUnauthorized, nil, "Invalid code_verifier")
			return
		}
	}

	// 4. Generate Tokens
	
	// Access Token: Sign with CLIENT's Private Key
	accessToken, err := utils.GenerateAccessToken(client.PrivateKey, data.UserID, data.ClientID, h.Config.AccessTokenExp)
	if err != nil {
		h.RespondInternalError(c, err, 3003)
		return
	}

	// Refresh Token: Sign with Server Symmetric Secret (Config.EncryptionKey or JWTSecret? Prompt says "environment variable")
	// I'll use JWTSecret.
	refreshToken, err := utils.GenerateRefreshToken(h.Config.JWTSecret, data.UserID, data.ClientID, h.Config.RefreshTokenExp)
	if err != nil {
		h.RespondInternalError(c, err, 3004)
		return
	}

	// 5. Return Response
	
	slog.Info("Token exchanged", "client_id", client.ID, "user_id", data.UserID)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    h.Config.AccessTokenExp * 60,
	})
}

func (h *Handler) OAuthRefresh(c *gin.Context) {
	// 1. Read Refresh Token from Body
	var req RefreshRequest
	if h.BindJSONWithValidation(c, &req) {
		return
	}
	refreshToken := req.RefreshToken

	// 2. Validate Refresh Token
	token, claims, err := utils.ValidateRefreshToken(refreshToken, h.Config.JWTSecret)
	if err != nil || !token.Valid {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid refresh token")
		return
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid token claims: sub")
		return
	}
	clientID, ok := claims["aud"].(string)
	if !ok {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid token claims: aud")
		return
	}

	// 3. Get Client to get Private Key
	var client models.Client
	if err := h.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Client not found")
		return
	}

	// 4. Create New Access Token
	accessToken, err := utils.GenerateAccessToken(client.PrivateKey, userID, clientID, h.Config.AccessTokenExp)
	if err != nil {
		h.RespondInternalError(c, err, 3005)
		return
	}

	slog.Info("Token refreshed", "client_id", client.ID, "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   h.Config.AccessTokenExp * 60,
	})
}
