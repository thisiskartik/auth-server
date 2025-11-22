package handlers

import (
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type TokenRequest struct {
	Code         string `json:"code" binding:"required"`
	CodeVerifier string `json:"code_verifier"` // Optional in strict prompt, but needed for PKCE
}

func (h *Handler) OAuthToken(c *gin.Context) {
	// 1. Basic Auth
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		h.RespondError(c, http.StatusUnauthorized, nil, "Basic auth required")
		return
	}

	// Authenticate Client
	var client models.Client
	if err := h.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid Client")
		return
	}

	// Decrypt secret to compare
	decryptedSecret, err := utils.Decrypt(client.Secret, h.Config.EncryptionKey)
	if err != nil {
		h.RespondInternalError(c, err, 3001)
		return
	}

	if decryptedSecret != clientSecret {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid Client Secret")
		return
	}

	// 2. Read Request
	var req TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.RespondError(c, http.StatusBadRequest, err, err.Error())
		return
	}

	// 3. Check Redis for Code
	val, err := h.RedisClient.Get(context.Background(), req.Code).Result()
	if err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid or expired code")
		return
	}

	var data AuthCodeData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		h.RespondInternalError(c, err, 3002)
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

	// 5. Delete Code (Single use)
	h.RedisClient.Del(context.Background(), req.Code)

	// 6. Return Response
	// Refresh Token in HTTP Only Cookie
	// "Returns the `access_token` in the body and `refresh_token` in the http only cookie."
	
	c.SetCookie("refresh_token", refreshToken, h.Config.RefreshTokenExp*24*60*60, "/", "", false, true) // Secure=false for dev
	
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   h.Config.AccessTokenExp * 60,
	})
}

func (h *Handler) OAuthRefresh(c *gin.Context) {
	// 1. Read Refresh Token from Cookie
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Refresh token missing")
		return
	}

	// 2. Validate Refresh Token
	token, claims, err := utils.ValidateRefreshToken(refreshToken, h.Config.JWTSecret)
	if err != nil || !token.Valid {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid refresh token")
		return
	}

	userID := claims["sub"].(string)
	clientID := claims["aud"].(string)

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

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   h.Config.AccessTokenExp * 60,
	})
}
