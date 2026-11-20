package domain

import "errors"

var (
	ErrEmailAlreadyExists  = errors.New("email address is already registered")
	ErrInvalidCredentials  = errors.New("invalid email or password")
	ErrAccountDisabled     = errors.New("user account is disabled")
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
	ErrUserNotFound        = errors.New("user not found")
)
