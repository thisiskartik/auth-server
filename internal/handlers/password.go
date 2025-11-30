package handlers

import (
	"auth-system/internal/middleware"
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if h.BindJSONWithValidation(c, &req) {
		return
	}

	// Check if user exists
	var user models.User
	if err := h.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Don't reveal if user exists or not for security
		// Return success even if user doesn't exist
		traceID, _ := c.Get(middleware.TraceIDKey)
		slog.Info("Password reset requested", "email", req.Email, "trace_id", traceID)
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a password reset link has been sent"})
		return
	}

	// Generate random code
	resetCode, err := utils.GenerateRandomString(32)
	if err != nil {
		h.RespondInternalError(c, err, 5001)
		return
	}

	// Calculate expiration duration
	expirationHours := h.Config.PasswordResetExpHours
	if expirationHours == 0 {
		// Default to 24 hours if not configured
		expirationHours = 24
	}
	expiration := time.Duration(expirationHours) * time.Hour

	// Store code in Redis with expiration
	// Key format: user:password:reset:{email} -> code
	key := "user:password:reset:" + req.Email
	err = h.RedisClient.Set(c, key, resetCode, expiration).Err()
	if err != nil {
		h.RespondInternalError(c, err, 5002)
		return
	}

	// Send password reset email
	utils.SendPasswordResetEmail(c, user.Email, resetCode)

	traceID, _ := c.Get(middleware.TraceIDKey)
	slog.Info("Password reset code generated", "email", req.Email, "trace_id", traceID)
	c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a password reset link has been sent"})
}

func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	validationErrors, err := h.GetValidationErrors(c, &req)
	if err != nil {
		h.RespondError(c, http.StatusBadRequest, err, "Invalid JSON")
		return
	}
	if validationErrors == nil {
		validationErrors = make(map[string]any)
	}

	// Password complexity validation
	if req.NewPassword != "" {
		passErrors := validatePassword(req.NewPassword)
		if len(passErrors) > 0 {
			// Merge password errors
			if existing, ok := validationErrors["new_password"]; ok {
				var list []string
				if s, ok := existing.(string); ok {
					list = append(list, s)
				} else if l, ok := existing.([]string); ok {
					list = append(list, l...)
				}
				list = append(list, passErrors...)
				validationErrors["new_password"] = list
			} else {
				validationErrors["new_password"] = passErrors
			}
		}
	}

	if len(validationErrors) > 0 {
		h.RespondValidationError(c, validationErrors)
		return
	}

	// Retrieve code from Redis
	key := "user:password:reset:" + req.Email
	storedCode, err := h.RedisClient.Get(c, key).Result()
	if err != nil {
		// Could be expired or invalid email
		h.RespondError(c, http.StatusBadRequest, err, "Invalid or expired reset code")
		return
	}

	if storedCode != req.Code {
		h.RespondError(c, http.StatusBadRequest, nil, "Invalid reset code")
		return
	}

	// Find user
	var user models.User
	if err := h.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		h.RespondInternalError(c, err, 5003)
		return
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		h.RespondInternalError(c, err, 5004)
		return
	}

	// Update password
	user.Password = hashedPassword
	if err := h.DB.Save(&user).Error; err != nil {
		h.RespondInternalError(c, err, 5005)
		return
	}

	// Delete code from Redis after successful reset
	h.RedisClient.Del(c, key)

	traceID, _ := c.Get(middleware.TraceIDKey)
	slog.Info("Password reset successful", "email", req.Email, "trace_id", traceID)
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}
