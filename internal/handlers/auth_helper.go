package handlers

import (
	"auth-system/internal/models"
	"auth-system/internal/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) authenticateClient(c *gin.Context) (*models.Client, bool) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		h.RespondError(c, http.StatusUnauthorized, nil, "Basic auth required")
		return nil, false
	}

	var client models.Client
	if err := h.DB.Where("id = ?", clientID).First(&client).Error; err != nil {
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid Client")
		return nil, false
	}

	// Compare Hash
	if !utils.CheckPassword(clientSecret, client.Secret) {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid Client Secret")
		return nil, false
	}

	return &client, true
}
