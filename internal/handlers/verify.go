package handlers

import (
	"auth-system/internal/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type VerifyEmailRequest struct {
	Code string `json:"code" binding:"required"`
}

func (h *Handler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.RespondError(c, http.StatusBadRequest, err, "Invalid JSON")
		return
	}

	// Retrieve user ID from Redis
	key := "user:verification:" + req.Code
	userIDStr, err := h.RedisClient.Get(c, key).Result()
	if err != nil {
		h.RespondError(c, http.StatusBadRequest, err, "Invalid or expired verification code")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.RespondInternalError(c, err, 2001)
		return
	}

	// Update user verified status
	var user models.User
	if err := h.DB.First(&user, userID).Error; err != nil {
		h.RespondInternalError(c, err, 2002)
		return
	}

	if user.Verified {
		c.JSON(http.StatusOK, gin.H{"message": "Email already verified"})
		return
	}

	user.Verified = true
	if err := h.DB.Save(&user).Error; err != nil {
		h.RespondInternalError(c, err, 2003)
		return
	}

	// Delete code from Redis
	h.RedisClient.Del(c, key)

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}
