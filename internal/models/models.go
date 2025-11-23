package models

import (
	"time"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	FirstName string    `gorm:"not null"`
	LastName  string    `gorm:"not null"`
	Email     string    `gorm:"uniqueIndex;not null"`
	Password  string    `gorm:"not null"`
	Verified  bool      `gorm:"default:false"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Client struct {
	ID         uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name       string    `gorm:"uniqueIndex;not null"`
	FrontendURI string    `gorm:"not null"`
	Secret     string    `gorm:"not null"` // Encrypted
	PrivateKey string    `gorm:"not null"` // PEM encoded
	PublicKey  string    `gorm:"not null"` // PEM encoded
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (user *User) BeforeCreate(tx *gorm.DB) (err error) {
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	return
}

func (client *Client) BeforeCreate(tx *gorm.DB) (err error) {
	if client.ID == uuid.Nil {
		client.ID = uuid.New()
	}
	return
}
