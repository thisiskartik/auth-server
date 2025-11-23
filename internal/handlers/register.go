package handlers

import (
	"auth-system/internal/middleware"
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type RegisterRequest struct {
	Type      string `json:"type" binding:"required,oneof=user client"`
	Name      string `json:"name"`                            // Client only
	FirstName string `json:"first_name"`                      // User only
	LastName  string `json:"last_name"`                       // User only
	Email     string `json:"email" binding:"omitempty,email"` // User only
	Password  string `json:"password"`                        // User only
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	validationErrors := make(map[string]any)

	// 1. Bind and Validate Struct Tags
	if err := c.ShouldBindJSON(&req); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			// Collect struct validation errors but DO NOT RETURN yet
			for _, fe := range ve {
				fieldName := fe.Field()
				if field, ok := reflect.TypeOf(&req).Elem().FieldByName(fe.StructField()); ok {
					if tag := field.Tag.Get("json"); tag != "" {
						fieldName = strings.Split(tag, ",")[0]
					}
				}
				validationErrors[fieldName] = msgForTag(fe.Tag())
			}
		} else {
			// JSON Parsing Error (Syntax) - Return immediately
			h.RespondError(c, http.StatusBadRequest, err, "Invalid JSON")
			return
		}
	}

	// 2. Manual Validations based on Type
	// We proceed even if struct validation failed, to catch other errors.
	if req.Type == "user" {
		userErrors := h.validateUserReq(req)
		mergeErrors(validationErrors, userErrors)
	} else if req.Type == "client" {
		clientErrors := h.validateClientReq(req)
		mergeErrors(validationErrors, clientErrors)
	}

	// 3. Check if any errors exist
	if len(validationErrors) > 0 {
		h.RespondValidationError(c, validationErrors)
		return
	}

	// 4. Create Resource
	if req.Type == "user" {
		h.createUser(c, req)
	} else {
		h.createClient(c, req)
	}
}

func mergeErrors(dest, src map[string]any) {
	for k, v := range src {
		if existing, ok := dest[k]; ok {
			// If collision, create list or append
			var list []string
			
			// Handle existing value
			switch val := existing.(type) {
			case string:
				list = append(list, val)
			case []string:
				list = append(list, val...)
			}

			// Handle new value
			switch val := v.(type) {
			case string:
				list = append(list, val)
			case []string:
				list = append(list, val...)
			}
			
			dest[k] = list
		} else {
			dest[k] = v
		}
	}
}

func (h *Handler) validateUserReq(req RegisterRequest) map[string]any {
	errors := make(map[string]any)

	if req.FirstName == "" {
		errors["first_name"] = "This field is required"
	}
	if req.LastName == "" {
		errors["last_name"] = "This field is required"
	}
	if req.Email == "" {
		errors["email"] = "This field is required"
	}
	if req.Password == "" {
		errors["password"] = "This field is required"
	}

	// Password complexity
	if req.Password != "" {
		passErrors := validatePassword(req.Password)
		if len(passErrors) > 0 {
			errors["password"] = passErrors
		}
	}

	// Check email unique (only if email is provided, otherwise redundant with required)
	if req.Email != "" {
		var count int64
		h.DB.Model(&models.User{}).Where("email = ?", req.Email).Count(&count)
		if count > 0 {
			// Check if we already have an error for email (e.g. from binder)
			// But here we return a fresh map, mergeErrors handles collision.
			errors["email"] = "Email already registered"
		}
	}

	return errors
}

func (h *Handler) validateClientReq(req RegisterRequest) map[string]any {
	errors := make(map[string]any)

	if req.Name == "" {
		errors["name"] = "This field is required"
	}

	// Check name unique
	if req.Name != "" {
		var count int64
		h.DB.Model(&models.Client{}).Where("name = ?", req.Name).Count(&count)
		if count > 0 {
			errors["name"] = "Client name already registered"
		}
	}

	return errors
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

func (h *Handler) createUser(c *gin.Context, req RegisterRequest) {
	// Validation already done

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

func (h *Handler) createClient(c *gin.Context, req RegisterRequest) {
	// Validation already done

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
