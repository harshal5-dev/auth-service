package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/harshal5-dev/auth-service/internal/domain"
	"github.com/harshal5-dev/auth-service/internal/security"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
}

type AuthService struct {
	users  UserRepository
	hasher *security.PasswordHasher
	logger *slog.Logger
}

func NewAuthService(
	users UserRepository,
	hasher *security.PasswordHasher,
	logger *slog.Logger,
) *AuthService {
	return &AuthService{
		users:  users,
		hasher: hasher,
		logger: logger,
	}
}

func (s *AuthService) Register(ctx context.Context, email, password string) (*domain.User, error) {
	normalizedEmail := normalizeEmail(email)

	passwordHash, err := s.hasher.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	userID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generate UUIDv7: %w", err)
	}

	newUser := &domain.User{
		ID:            userID,
		Email:         normalizedEmail,
		PasswordHash:  passwordHash,
		Roles:         []string{domain.RoleUser},
		IsActive:      true,
		EmailVerified: false,
	}

	return s.users.Create(ctx, newUser)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
