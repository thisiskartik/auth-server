package handlers

import (
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type RegisterRequest struct {
	Type      string `json:"type" binding:"required,oneof=user client"`
	Name      string `json:"name"` // Client only
	FirstName string `json:"first_name"` // User only
	LastName  string `json:"last_name"` // User only
	Email     string `json:"email"` // User only
	Password  string `json:"password"` // User only
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.RespondError(c, http.StatusBadRequest, err, err.Error())
		return
	}

	if req.Type == "user" {
		h.registerUser(c, req)
	} else {
		h.registerClient(c, req)
	}
}

func (h *Handler) registerUser(c *gin.Context, req RegisterRequest) {
	// Validation
	if req.FirstName == "" || req.LastName == "" || req.Email == "" || req.Password == "" {
		h.RespondError(c, http.StatusBadRequest, nil, "Missing required fields for user")
		return
	}

	// Password complexity
	if !isValidPassword(req.Password) {
		h.RespondError(c, http.StatusBadRequest, nil, "Password does not meet complexity requirements")
		return
	}

	// Check email unique
	var count int64
	h.DB.Model(&models.User{}).Where("email = ?", req.Email).Count(&count)
	if count > 0 {
		h.RespondError(c, http.StatusBadRequest, nil, "Email already registered")
		return
	}

	// Encrypt password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		h.RespondInternalError(c, err, ErrCrypto)
		return
	}

	user := models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  hashedPassword,
	}

	if err := h.DB.Create(&user).Error; err != nil {
		h.RespondInternalError(c, err, ErrDatabase)
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (h *Handler) registerClient(c *gin.Context, req RegisterRequest) {
	// Validation
	if req.Name == "" {
		h.RespondError(c, http.StatusBadRequest, nil, "Name required for client")
		return
	}

	// Check name unique
	var count int64
	h.DB.Model(&models.Client{}).Where("name = ?", req.Name).Count(&count)
	if count > 0 {
		h.RespondError(c, http.StatusBadRequest, nil, "Client name already registered")
		return
	}

	// Generate Secret
	secret, err := utils.GenerateRandomString(32)
	if err != nil {
		h.RespondInternalError(c, err, ErrCrypto)
		return
	}

	// Encrypt Secret
	encryptedSecret, err := utils.Encrypt(secret, h.Config.EncryptionKey)
	if err != nil {
		h.RespondInternalError(c, err, ErrCrypto)
		return
	}

	// Generate Keys
	privKey, pubKey, err := utils.GenerateRSAKeyPair()
	if err != nil {
		h.RespondInternalError(c, err, ErrCrypto)
		return
	}

	client := models.Client{
		Name:       req.Name,
		Secret:     encryptedSecret,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	if err := h.DB.Create(&client).Error; err != nil {
		h.RespondInternalError(c, err, ErrDatabase)
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
		Secret:    secret,
		PublicKey: client.PublicKey,
		CreatedAt: client.CreatedAt,
		UpdatedAt: client.UpdatedAt,
	}

	c.JSON(http.StatusCreated, response)
}

func isValidPassword(s string) bool {
	if len(s) < 8 {
		return false
	}
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(s)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(s)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(s)
	hasSymbol := regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(s)
	return hasUpper && hasLower && hasNumber && hasSymbol
}
