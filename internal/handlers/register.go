package handlers

import (
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type RegisterRequest struct {
	Type      string `json:"type" binding:"required,oneof=user client"`
	Name      string `json:"name"` // Client only
	FirstName string `json:"first_name"` // User only
	LastName  string `json:"last_name"` // User only
	Email     string `json:"email" binding:"omitempty,email"` // User only
	Password  string `json:"password"` // User only
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Handle Validator Errors
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			out := make(map[string]string)
			for _, fe := range ve {
				out[fe.Field()] = msgForTag(fe.Tag())
			}
			h.RespondValidationError(c, out)
			return
		}
		// Handle JSON Parsing Errors
		h.RespondError(c, http.StatusBadRequest, err, "Invalid JSON")
		return
	}

	if req.Type == "user" {
		h.registerUser(c, req)
	} else {
		h.registerClient(c, req)
	}
}

func msgForTag(tag string) string {
	switch tag {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email"
	case "oneof":
		return "Should be one of [user client]"
	}
	return "Invalid value"
}

func (h *Handler) registerUser(c *gin.Context, req RegisterRequest) {
	// Collect Errors
	validationErrors := make(map[string]string)

	if req.FirstName == "" {
		validationErrors["first_name"] = "This field is required"
	}
	if req.LastName == "" {
		validationErrors["last_name"] = "This field is required"
	}
	if req.Email == "" {
		validationErrors["email"] = "This field is required"
	}
	if req.Password == "" {
		validationErrors["password"] = "This field is required"
	}

	// Password complexity
	if req.Password != "" {
		passErrors := validatePassword(req.Password)
		if len(passErrors) > 0 {
			validationErrors["password"] = "Password must " + strings.Join(passErrors, ", ")
		}
	}

	if len(validationErrors) > 0 {
		h.RespondValidationError(c, validationErrors)
		return
	}

	// Check email unique
	var count int64
	h.DB.Model(&models.User{}).Where("email = ?", req.Email).Count(&count)
	if count > 0 {
		validationErrors["email"] = "Email already registered"
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

	slog.Info("User registered", "user_id", user.ID, "email", user.Email)
	c.JSON(http.StatusCreated, user)
}

func (h *Handler) registerClient(c *gin.Context, req RegisterRequest) {
	validationErrors := make(map[string]string)
	
	// Validation
	if req.Name == "" {
		validationErrors["name"] = "This field is required"
		h.RespondValidationError(c, validationErrors)
		return
	}

	// Check name unique
	var count int64
	h.DB.Model(&models.Client{}).Where("name = ?", req.Name).Count(&count)
	if count > 0 {
		validationErrors["name"] = "Client name already registered"
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

	slog.Info("Client registered", "client_id", client.ID, "client_name", client.Name)
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
