package handlers

import (
	"auth-system/internal/middleware"
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type UserRegisterRequest struct {
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
}

type ClientRegisterRequest struct {
	Name string `json:"name" binding:"required"`
}

func (h *Handler) RegisterUser(c *gin.Context) {
	var req UserRegisterRequest
	validationErrors, err := h.GetValidationErrors(c, &req)
	if err != nil {
		h.RespondError(c, http.StatusBadRequest, err, "Invalid JSON")
		return
	}
	if validationErrors == nil {
		validationErrors = make(map[string]any)
	}

	// Password complexity
	// We run this even if there are validation errors, because we want to show all errors.
	if req.Password != "" {
		passErrors := validatePassword(req.Password)
		if len(passErrors) > 0 {
			// Merge password errors
			if existing, ok := validationErrors["password"]; ok {
				// convert existing to list and append
				var list []string
				if s, ok := existing.(string); ok {
					list = append(list, s)
				} else if l, ok := existing.([]string); ok {
					list = append(list, l...)
				}
				list = append(list, passErrors...)
				validationErrors["password"] = list
			} else {
				validationErrors["password"] = passErrors
			}
		}
	}

	// Check email unique
	if req.Email != "" {
		var count int64
		h.DB.Model(&models.User{}).Where("email = ?", req.Email).Count(&count)
		if count > 0 {
			MergeErrors(validationErrors, map[string]any{"email": "Email already registered"})
		}
	}

	if len(validationErrors) > 0 {
		h.RespondValidationError(c, validationErrors)
		return
	}

	// Encrypt password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		h.RespondInternalError(c, err, 1001)
		return
	}

	user := models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  hashedPassword,
	}

	if err := h.DB.Create(&user).Error; err != nil {
		h.RespondInternalError(c, err, 1002)
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
	err = h.RedisClient.Set(c, "user:verification:"+user.Email, verificationCode, 0).Err()
	if err != nil {
		h.RespondInternalError(c, err, 1008)
		return
	}

	// Send verification email
	traceID, _ := c.Get(middleware.TraceIDKey)
	traceIDStr, _ := traceID.(string)

	utils.SendVerificationEmail(user.Email, verificationCode, traceIDStr)

	// Create Response DTO
	response := struct {
		ID        uuid.UUID `json:"id"`
		FirstName string    `json:"first_name"`
		LastName  string    `json:"last_name"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	traceID, _ := c.Get(middleware.TraceIDKey)
	slog.Info("User registered", "user_id", user.ID, "email", user.Email, "trace_id", traceID)
	c.JSON(http.StatusCreated, response)
}

func (h *Handler) RegisterClient(c *gin.Context) {
	var req ClientRegisterRequest
	validationErrors, err := h.GetValidationErrors(c, &req)
	if err != nil {
		h.RespondError(c, http.StatusBadRequest, err, "Invalid JSON")
		return
	}
	if validationErrors == nil {
		validationErrors = make(map[string]any)
	}

	// Check name unique
	if req.Name != "" {
		var count int64
		h.DB.Model(&models.Client{}).Where("name = ?", req.Name).Count(&count)
		if count > 0 {
			MergeErrors(validationErrors, map[string]any{"name": "Client name already registered"})
		}
	}

	if len(validationErrors) > 0 {
		h.RespondValidationError(c, validationErrors)
		return
	}

	// Generate Secret
	secret, err := utils.GenerateRandomString(32)
	if err != nil {
		h.RespondInternalError(c, err, 1003)
		return
	}

	// Hash Secret
	hashedSecret, err := utils.HashPassword(secret)
	if err != nil {
		h.RespondInternalError(c, err, 1004)
		return
	}

	// Generate Keys
	privKey, pubKey, err := utils.GenerateRSAKeyPair()
	if err != nil {
		h.RespondInternalError(c, err, 1005)
		return
	}

	client := models.Client{
		Name:       req.Name,
		Secret:     hashedSecret,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	if err := h.DB.Create(&client).Error; err != nil {
		h.RespondInternalError(c, err, 1006)
		return
	}

	response := struct {
		ID        uuid.UUID `json:"id"`
		Name      string    `json:"name"`
		Secret    string    `json:"secret"`
		PublicKey string    `json:"public_key"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}{
		ID:        client.ID,
		Name:      client.Name,
		Secret:    secret, // Return PLAIN secret once
		PublicKey: client.PublicKey,
		CreatedAt: client.CreatedAt,
		UpdatedAt: client.UpdatedAt,
	}

	traceID, _ := c.Get(middleware.TraceIDKey)
	slog.Info("Client registered", "client_id", client.ID, "client_name", client.Name, "trace_id", traceID)
	c.JSON(http.StatusCreated, response)
}

func validatePassword(s string) []string {
	var errors []string
	if len(s) < 8 {
		errors = append(errors, "be at least 8 characters long")
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(s) {
		errors = append(errors, "contain at least one uppercase letter")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(s) {
		errors = append(errors, "contain at least one lowercase letter")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(s) {
		errors = append(errors, "contain at least one number")
	}
	if !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(s) {
		errors = append(errors, "contain at least one special character")
	}
	return errors
}
