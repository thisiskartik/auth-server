package handlers

import (
	"auth-system/internal/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type VerifyEmailRequest struct {
	Code  string `json:"code" binding:"required"`
	Email string `json:"email" binding:"required,email"`
}

type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func (h *Handler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if h.BindJSONWithValidation(c, &req) {
		return
	}

	// Retrieve code from Redis
	key := "user:verification:" + req.Email
	storedCode, err := h.RedisClient.Get(c, key).Result()
	if err != nil {
		// Could be expired or invalid email
		h.RespondError(c, http.StatusBadRequest, err, "Invalid or expired verification code")
		return
	}

	if storedCode != req.Code {
		h.RespondError(c, http.StatusBadRequest, nil, "Invalid verification code")
		return
	}

	// Find user
	var user models.User
	if err := h.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
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

func (h *Handler) ResendVerificationCode(c *gin.Context) {
	var req ResendVerificationRequest
	if h.BindJSONWithValidation(c, &req) {
		return
	}

	// Check if user exists and is not verified
	var user models.User
	if err := h.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		h.RespondError(c, http.StatusNotFound, err, "User not found")
		return
	}

	if user.Verified {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Email already verified"})
		return
	}

	// Generate verification code
	verificationCode, err := utils.GenerateRandomDigits(6)
	if err != nil {
		h.RespondInternalError(c, err, 1007)
		return
	}

	// Store verification code in Redis
	// Key: user:verification:{email} -> code
	err = h.RedisClient.Set(c, "user:verification:"+req.Email, verificationCode, 0).Err()
	if err != nil {
		h.RespondInternalError(c, err, 1008)
		return
	}

	// Send verification email
	traceID, _ := c.Get(middleware.TraceIDKey)
	traceIDStr, _ := traceID.(string)

	utils.SendVerificationEmail(user.Email, verificationCode, traceIDStr)

	c.JSON(http.StatusOK, gin.H{"message": "Verification code resent successfully"})
}

