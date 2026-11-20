package domain

import (
	"time"

	"github.com/google/uuid"
)

type RefreshSession struct {
	UserID    uuid.UUID `json:"userID"`
	UserAgent string    `json:"userAgent"`
	ClientIP  string    `json:"clientIP"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TokenPair struct {
	AccessToken     string
	AccessExpiresIn int64
	RawRefreshToken string
	RefreshTTL      time.Duration
}
