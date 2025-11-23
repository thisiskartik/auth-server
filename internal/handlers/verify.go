package handlers

import (
	"auth-system/internal/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (h *Handler) VerifyEmail(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("<h1>Missing verification code</h1>"))
		return
	}

	// Retrieve user ID from Redis
	key := "user:verification:" + code
	userIDStr, err := h.RedisClient.Get(c, key).Result()
	if err != nil {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("<h1>Invalid or expired verification code</h1>"))
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
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<h1>Email already verified</h1>"))
		return
	}

	user.Verified = true
	if err := h.DB.Save(&user).Error; err != nil {
		h.RespondInternalError(c, err, 2003)
		return
	}

	// Delete code from Redis
	h.RedisClient.Del(c, key)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<h1>Email verified successfully</h1>"))
}
