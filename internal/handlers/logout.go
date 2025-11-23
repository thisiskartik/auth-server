package handlers

import (
	"auth-system/internal/utils"
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *Handler) Logout(c *gin.Context) {
	// 1. Read Refresh Token from Body
	var req LogoutRequest
	if h.BindJSONWithValidation(c, &req) {
		return
	}

	// 2. Validate Refresh Token
	token, claims, err := utils.ValidateRefreshToken(req.RefreshToken, h.Config.JWTSecret)
	if err != nil {
		// If the token is invalid or signature is wrong, we return Unauthorized.
		h.RespondError(c, http.StatusUnauthorized, err, "Invalid refresh token")
		return
	}

	if !token.Valid {
		h.RespondError(c, http.StatusUnauthorized, nil, "Invalid refresh token")
		return
	}

	// 3. Calculate TTL
	var ttl time.Duration
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		ttl = time.Until(expTime)
	} else {
		// If exp claim is missing, block indefinitely.
		// In go-redis, a duration of 0 means the key has no expiration time (persistent).
		ttl = 0
	}

	// 4. Block Token in Redis
	// Key format: blocked_refresh_token:{refresh_token}
	key := "blocked_refresh_token:" + req.RefreshToken
	err = h.RedisClient.Set(context.Background(), key, "blocked", ttl).Err()
	if err != nil {
		h.RespondInternalError(c, err, 4001)
		return
	}

	slog.Info("RefreshToken blocked", "key", key, "ttl", ttl)
	c.Status(http.StatusNoContent)
}
