package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/harshal5-dev/auth-service/internal/domain"
	"github.com/harshal5-dev/auth-service/internal/repository/postgres/sqlc"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pgUniqueViolationCode = "23505"

type UserRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	row, err := r.queries.CreateUser(ctx, sqlc.CreateUserParams{
		ID:            user.ID,
		Email:         user.Email,
		PasswordHash:  user.PasswordHash,
		Roles:         user.Roles,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolationCode {
			return nil, domain.ErrEmailAlreadyExists
		}
		return nil, fmt.Errorf("postgres CreateUser: %w", err)
	}

	return mapToDomainUser(row), nil
}

func mapToDomainUser(row sqlc.User) *domain.User {
	return &domain.User{
		ID:            row.ID,
		Email:         row.Email,
		PasswordHash:  row.PasswordHash,
		Roles:         row.Roles,
		IsActive:      row.IsActive,
		EmailVerified: row.EmailVerified,
		LastLoginAt:   row.LastLoginAt,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}
