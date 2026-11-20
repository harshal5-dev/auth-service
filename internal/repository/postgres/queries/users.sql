-- name: CreateUser :one
INSERT INTO users (
    id,
    email,
    password_hash,
    roles,
    is_active,
    email_verified
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, email, password_hash, roles, is_active, email_verified, last_login_at, created_at, updated_at;

-- name: GetUserByEmail :one
SELECT
    id,
    email,
    password_hash,
    roles,
    is_active,
    email_verified,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE email = $1
LIMIT 1;

-- name: GetUserByID :one
SELECT
    id,
    email,
    password_hash,
    roles,
    is_active,
    email_verified,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE id = $1
LIMIT 1;

-- name: UpdateLastLogin :exec
UPDATE users
SET last_login_at = NOW(), updated_at = NOW()
WHERE id = $1;
