package httpapi

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	minPasswordLen = 8
	maxPasswordLen = 128
	maxEmailLen    = 254
)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *RegisterRequest) Validate() error {
	return validateCredentials(r.Email, r.Password)
}

func validateCredentials(email, password string) error {
	trimmedEmail := strings.TrimSpace(email)
	if trimmedEmail == "" || len(trimmedEmail) > maxEmailLen {
		return fmt.Errorf("a valid email address is required")
	}
	parsedAddr, err := mail.ParseAddress(trimmedEmail)
	if err != nil || parsedAddr.Address != trimmedEmail {
		return fmt.Errorf("invalid email address format")
	}

	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters long", minPasswordLen)
	}
	if len(password) > maxPasswordLen {
		return fmt.Errorf("password must not exceed %d characters", maxPasswordLen)
	}
	return nil
}

type UserDTO struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"createdAt"`
}

type RegisterResponse struct {
	User UserDTO `json:"user"`
}
