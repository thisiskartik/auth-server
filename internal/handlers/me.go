package handlers

import (
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func (h *Handler) ClientMe(c *gin.Context) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		h.RespondError(c, http.StatusUnauthorized, nil, "Basic auth required")
		return
	}

	var client models.Client
	if err := h.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid Client")
		return
	}

	decryptedSecret, err := utils.Decrypt(client.Secret, h.Config.EncryptionKey)
	if err != nil {
		h.RespondInternalError(c, err, 4001)
		return
	}

	if decryptedSecret != clientSecret {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid Client Secret")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":       client.Name,
		"public_key": client.PublicKey,
	})
}

func (h *Handler) UserMe(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		h.RespondError(c, http.StatusUnauthorized, nil, "Authorization header required")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid authorization format")
		return
	}

	tokenString := parts[1]

	// 1. Parse Unverified to get Audience (Client ID)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid token format")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid token claims")
		return
	}

	clientID, ok := claims["aud"].(string)
	if !ok {
		h.RespondError(c, http.StatusUnauthorized, nil, "Token missing audience")
		return
	}

	// 2. Fetch Client Public Key
	var client models.Client
	if err := h.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Client not found")
		return
	}

	// 3. Validate Token with Public Key
	validToken, validClaims, err := utils.ValidateAccessToken(tokenString, client.PublicKey)
	if err != nil || !validToken.Valid {
		h.RespondError(c, http.StatusUnauthorized, err, fmt.Sprintf("Invalid token signature: %v", err))
		return
	}

	// 4. Fetch User Details
	userID := validClaims["sub"].(string)
	var user models.User
	if err := h.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		h.RespondError(c, http.StatusNotFound, err, "User not found")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":       user.FirstName + " " + user.LastName,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
	})
}
