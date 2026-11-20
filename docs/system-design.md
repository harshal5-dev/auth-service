# `auth-service` — System Design Document

**Status:** Finalized (v0.1 MVP Specification)  
**Last Updated:** 2026-11-17  
**Language & Runtime:** Go 1.23+  

---

## 1. Overview & Design Goals

`auth-service` is a lightweight, high-performance authentication and token-issuance microservice written in Go. It serves as the centralized identity provider for a microservice ecosystem while allowing downstream services to verify requests **completely statelessly** in memory.

### Non-Negotiable Architectural Invariants
1. **Asymmetric Signing (`Ed25519` / `EdDSA`):** `auth-service` is the *only* component holding the **Ed25519 Private Key**. All downstream microservices verify tokens locally using the **Ed25519 Public Key** exposed via `/.well-known/jwks.json`.
2. **Dual-Token Session Model:**
   - **Access Token (Stateless JWT):** 15-minute lifespan, carried in `Authorization: Bearer <token>`, containing minimal identity and authorization claims (`sub`, `jti`, `roles`). Zero PII.
   - **Refresh Token (Stateful Opaque Token):** 7-day lifespan, 32-byte cryptographically random secret stored in an `HttpOnly` cookie on the client and as a **SHA-256 hash** in Redis. Rotated atomically on every use.
3. **Memory-Hard Password Storage (`Argon2id`):** User passwords are salted with 16 random bytes and hashed via `Argon2id`, stored in self-describing PHC string format in PostgreSQL.

---

## 2. Version-by-Version Delivery Roadmap

To avoid scope creep and ship a rock-solid foundation first, `auth-service` is designed around four incremental releases:

| Version | Milestone Name | Scope & Deliverables |
| :--- | :--- | :--- |
| **v0.1.0 (MVP)** | **Core Auth & Stateless Verification** | • User Registration (`POST /api/v1/auth/register`)<br>• User Login with Dual-Token Issuance (`POST /api/v1/auth/login`)<br>• Single-Use Refresh Token Rotation (`POST /api/v1/auth/refresh`)<br>• Single-Session Logout (`POST /api/v1/auth/logout`)<br>• Public Key Discovery (`GET /.well-known/jwks.json`)<br>• Liveness & Readiness Probes (`GET /healthz`, `GET /readyz`) |
| **v0.2.0** | **Multi-Device Sessions & Theft Detection** | • Logout from all devices (`POST /api/v1/auth/logout-all`)<br>• List & revoke active device sessions (`GET /api/v1/auth/sessions`, `DELETE /api/v1/auth/sessions/:id`)<br>• Refresh Token Family tracking (detect reuse of rotated tokens and revoke all user sessions)<br>• Instant user ban / JWT blocklist (`blacklist:user:<id>` in Redis with 15m TTL) |
| **v0.3.0** | **Account Lifecycle & Abuse Protection** | • Redis sliding-window Rate Limiting (per-IP and per-email on `/login` and `/register`)<br>• Change Password (`POST /api/v1/auth/change-password` + automatic `logout-all`)<br>• Forgot / Reset Password flow (`POST /api/v1/auth/forgot-password`, `POST /api/v1/auth/reset-password`)<br>• Email Verification token flow (`POST /api/v1/auth/verify-email`) |
| **v1.0.0** | **Enterprise Hardening & Key Rotation** | • Multi-key JWKS support for zero-downtime Ed25519 key rotation<br>• Persistent security audit trail (`auth_audit_logs` table)<br>• Downstream Go verifier middleware SDK package (`pkg/authmw`)<br>• Optional OAuth2 / OIDC social login providers (Google, GitHub) |

> [!IMPORTANT]
> **The rest of this document specifies v0.1.0 (MVP) in full detail**, while ensuring the database schema and package boundaries require zero breaking changes when moving to v0.2.0–v1.0.0.

---

## 3. Technology & Go Package Decisions (v0.1 MVP)

### 3.1 Core Cryptography & Auth Packages
| Responsibility | Package | Key Decision & Rationale |
| :--- | :--- | :--- |
| **JWT Creation & Parsing** | `github.com/golang-jwt/jwt/v5` | Strict claim validation, native `jwt.SigningMethodEdDSA` support, built-in leeway/clock-skew configuration. |
| **Asymmetric Signing** | `crypto/ed25519` *(stdlib)* | 32-byte keys, 64-byte compact signatures, immune to timing side-channels, significantly faster and smaller than RSA-2048/4096. |
| **Password Hashing** | `golang.org/x/crypto/argon2` + `crypto/subtle` | OWASP #1 recommendation (`Argon2id`). Verified with `subtle.ConstantTimeCompare` to prevent timing attacks. |
| **Opaque Token & Hashing** | `crypto/rand` + `crypto/sha256` *(stdlib)* | 32 bytes (256 bits of entropy) encoded as Base64URL for the client cookie; hashed with SHA-256 before touching Redis. |
| **Session & Token Store** | `github.com/redis/go-redis/v9` | Supports atomic `GETDEL` (Redis 6.2+) to guarantee single-use refresh token rotation without race conditions. |

### 3.2 HTTP, Database & Infrastructure Packages
| Responsibility | Selected Package / Tool | Why This Over Alternatives |
| :--- | :--- | :--- |
| **HTTP Router** | `net/http` (`http.ServeMux` — Go 1.22+ stdlib) | Zero external dependencies, native method + path routing (`POST /api/v1/auth/login`), composable standard `http.Handler` middleware chain. |
| **PostgreSQL Driver** | `github.com/jackc/pgx/v5/pgxpool` | Native Go binary protocol driver with built-in high-performance connection pooling and native `UUID` / `TEXT[]` support. |
| **Data Access / Codegen** | `sqlc` (`github.com/sqlc-dev/sqlc`) + `pgx/v5` | Compiles annotated `.sql` queries into 100% type-safe, zero-reflection Go code backed by `pgx/v5`. |
| **DB Migrations** | `github.com/pressly/goose/v3` | Supports single-file `.sql` migrations with `-- +goose Up` and `-- +goose Down` annotations runnable via CLI or embedded Go binary. |
| **UUID Generation** | `github.com/google/uuid` | Supports **UUIDv7** (`uuid.NewV7()`) for time-ordered database primary keys and **UUIDv4** (`uuid.NewString()`) for JWT `jti` claims. |
| **Configuration** | `github.com/caarlos0/env/v11` | Parses environment variables into a validated, strongly-typed Go struct at startup. |
| **Structured Logging** | `log/slog` *(stdlib)* | Zero-dependency structured JSON logging built directly into the Go standard library. |

---

## 4. Package & Directory Structure Design

We follow a clean, domain-centric Go project layout. Dependencies flow strictly inward:
`transport/httpapi` → `service` → `repository` / `security` → `domain`.

```text
auth-service/
├── cmd/
│   └── api/
│       └── main.go                   # Bootstraps config, logger, Postgres pool, Redis client, HTTP server & graceful shutdown
├── internal/
│   ├── config/
│   │   └── config.go                 # Environment variable struct & startup validation
│   ├── domain/
│   │   ├── user.go                   # User model, Role type & constants
│   │   ├── session.go                # RefreshSession metadata model
│   │   └── errors.go                 # Sentinel domain errors (ErrInvalidCredentials, ErrEmailTaken, ErrSessionExpired, etc.)
│   ├── security/                     # Named `security` so it never collides with Go's stdlib `crypto`
│   │   ├── argon2.go                 # Argon2id PHC string hashing, parsing, and constant-time verification
│   │   ├── jwt.go                    # Ed25519 JWT signing, claims struct, and JWKS JSON representation
│   │   └── opaque.go                 # 32-byte crypto/rand token generator and SHA-256 hex digest helper
│   ├── repository/
│   │   ├── postgres/
│   │   │   ├── queries/
│   │   │   │   └── users.sql         # Annotated sqlc SQL queries (CreateUser, GetUserByEmail, GetUserByID, UpdateLastLogin)
│   │   │   ├── sqlc/                 # Auto-generated by sqlc (db.go, models.go, users.sql.go)
│   │   │   └── user_repo.go          # Domain repository adapter wrapping sqlc Queries + pgxpool
│   │   └── redis/
│   │       └── session_repo.go       # Redis implementation of Refresh Token storage (Save, Consume/GetDel, Delete)
│   ├── service/
│   │   └── auth_service.go           # Orchestrates Register, Login, Refresh, and Logout business workflows
│   └── transport/
│       └── httpapi/                  # Named `httpapi` so it never collides with Go's stdlib `net/http`
│           ├── router.go             # stdlib http.ServeMux wiring ("POST /api/v1/auth/login", middleware chain)
│           ├── middleware.go         # Standard net/http middleware (RequestID, Structured Logger, Panic Recovery)
│           ├── handler.go            # HTTP handlers: decode DTOs, invoke AuthService, set/clear cookies
│           ├── dto.go                # Request/Response payloads & input validation rules
│           ├── cookie.go             # Centralized HttpOnly cookie builder & reader
│           └── response.go           # Uniform JSON response & error mapping helper
├── migrations/
│   └── 00001_create_users_table.sql  # Goose SQL migration (-- +goose Up / -- +goose Down)
├── docs/
│   └── system-design.md              # System Design Document
├── sqlc.yaml                         # sqlc configuration targeting pgx/v5
├── docker-compose.yml                # Local Postgres 16 + Redis 8 containers
├── Makefile                          # Developer commands (keygen, up, migrate-up, sqlc, run, test)
└── go.mod
```

### Why This Package Design Works
* **`internal/security` is pure and stateless:** Named `security` (avoiding name collisions with standard library `crypto`), it has zero dependency on Postgres, Redis, or HTTP. You can unit-test Argon2id hashing, Ed25519 signing, and JWKS formatting in milliseconds.
* **`internal/service` owns business rules, not HTTP details:** `AuthService` does not know about `http.Request` or cookies; it accepts typed structs and returns a `TokenPair` (`AccessToken`, `RawRefreshToken`, expiry times).
* **`internal/transport/httpapi` handles cookies and status codes:** Named `httpapi` (avoiding name collisions with standard library `net/http`), only this transport layer knows how to pack the `RawRefreshToken` into an `HttpOnly` cookie and map domain errors (like `domain.ErrInvalidCredentials`) to `401 Unauthorized`.

---

## 5. Database Design & Key Storage Decisions

`auth-service` uses a split-storage model:
* **PostgreSQL:** Source of truth for durable user identity and credentials.
* **Redis:** Source of truth for ephemeral, auto-expiring refresh token sessions.

```mermaid
erDiagram
    POSTGRES_USERS {
        UUID id PK "UUIDv7 (Time-ordered, generated in Go)"
        CITEXT email UK "Unique, case-insensitive email"
        TEXT password_hash "PHC format: $argon2id$v=19$m=65536,t=2,p=4$<salt>$<hash>"
        TEXT_ARRAY roles "Default: {'USER'}"
        BOOLEAN is_active "Default: true (false = suspended/banned)"
        BOOLEAN email_verified "Default: false (used in v0.3)"
        TIMESTAMPTZ last_login_at "Nullable timestamp of last login"
        TIMESTAMPTZ created_at "Default: NOW()"
        TIMESTAMPTZ updated_at "Default: NOW()"
    }

    REDIS_REFRESH_TOKEN {
        STRING key PK "refresh:<sha256_hex_hash> (TTL: 7 days)"
        UUID user_id "References POSTGRES_USERS.id"
        STRING user_agent "Client User-Agent metadata"
        STRING client_ip "Client IP address at login/refresh"
        TIMESTAMPTZ created_at "Session creation timestamp"
        TIMESTAMPTZ expires_at "Absolute expiration timestamp"
    }

    POSTGRES_USERS ||--o{ REDIS_REFRESH_TOKEN : "owns active sessions"
```

### 5.1 PostgreSQL Schema (`migrations/000001_init_users.up.sql`)

```sql
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id              UUID PRIMARY KEY,
    email           CITEXT NOT NULL CONSTRAINT uq_users_email UNIQUE,
    password_hash   TEXT NOT NULL,
    roles           TEXT[] NOT NULL DEFAULT ARRAY['USER']::TEXT[],
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 5.2 Key PostgreSQL Design Decisions

#### Decision 1: `UUIDv7` Primary Keys (Generated in Go)
* **Choice:** Generate `id` in Go via `uuid.NewV7()` rather than `SERIAL`/`BIGINT` or Postgres `gen_random_uuid()` (`UUIDv4`).
* **Why:**
  * Sequential integers (`1, 2, 3...`) leak total user count and are easy to guess if exposed in JWT `sub` claims.
  * Random `UUIDv4` values scatter inserts across the entire PostgreSQL B-Tree index, causing page splits and high disk I/O as the table grows.
  * `UUIDv7` embeds a millisecond Unix timestamp in the top 48 bits followed by cryptographic randomness—giving us globally unique, unguessable IDs that insert sequentially into PostgreSQL B-Tree indexes.

#### Decision 2: Self-Describing PHC String Format for `password_hash`
* **Choice:** Store the Argon2id output as a single standard PHC string in `password_hash` rather than separate `password_hash` and `salt` columns:
  ```text
  $argon2id$v=19$m=65536,t=2,p=4$<base64_raw_salt>$<base64_raw_hash>
  ```
* **Why:**
  * Every row records the exact memory (`m=65536` KiB = 64 MB), time cost (`t=2`), parallelism (`p=4`), and 16-byte salt used when that specific password was hashed.
  * If we upgrade our hardware in the future and increase `m` to `131072` (128 MB), existing users can still log in without breaking, and `auth-service` can transparently re-hash their password to the new parameters upon their next login.

#### Decision 3: Case-Insensitive Email (`CITEXT` + Go Normalization)
* **Choice:** Normalize emails in Go (`strings.ToLower(strings.TrimSpace(email))`) AND use PostgreSQL's `CITEXT` type with a `UNIQUE` constraint.
* **Why:** Guarantees `Alice@Example.com` and `alice@example.com` can never register as two distinct accounts, even if data is inserted directly via SQL scripts.

#### Decision 4: `roles TEXT[]` on `users` for MVP
* **Choice:** Store roles as a native Postgres text array (`ARRAY['USER']`) directly on the `users` table for MVP instead of creating separate `roles` and `user_roles` join tables.
* **Why:**
  * In a JWT-based microservice architecture, `auth-service`'s primary job is to embed role strings (`["USER", "ADMIN"]`) into the JWT `roles` claim.
  * Storing `TEXT[]` on `users` means login and token refresh require a single primary-key/index lookup with **zero SQL JOINs**.
  * Separate RBAC permission tables can be added in v1.0 if fine-grained dynamic permissions are required.

#### Decision 5: Including `is_active` and `email_verified` in MVP Table
* **Choice:** Include `is_active` (`DEFAULT TRUE`) and `email_verified` (`DEFAULT FALSE`) now.
* **Why:**
  * `is_active` allows immediate account deactivation: if `is_active == false`, both `/login` and `/refresh` reject the user immediately.
  * `email_verified` avoids an `ALTER TABLE` migration when v0.3 adds email verification.

---

### 5.3 Redis Schema & Session Storage Design

#### How Opaque Refresh Tokens Work
1. `auth-service` generates 32 cryptographically random bytes via `crypto/rand.Read`.
2. Those 32 bytes are encoded using **Base64 RawURL** (43 characters, URL/cookie-safe) → this is the **`raw_refresh_token`** sent *only* to the client's `HttpOnly` cookie.
3. `auth-service` computes `sha256.Sum256([]byte(raw_refresh_token))` and encodes it as a 64-character hex string → this is the **`token_hash`** used in Redis.

#### Redis Key & Value Structure (v0.1 MVP)
* **Redis Key:** `refresh:<sha256_hex_hash>`
* **Redis TTL:** `604800` seconds (`7 days`)
* **Redis Value (JSON):**
  ```json
  {
    "user_id": "01933b4a-7c80-7000-8000-123456789abc",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "client_ip": "192.0.2.10",
    "created_at": "2026-11-17T08:50:00Z",
    "expires_at": "2026-11-24T08:50:00Z"
  }
  ```

#### Key Decision: Should `/auth/refresh` Query PostgreSQL or Only Redis?
* **Choice:** During `POST /api/v1/auth/refresh`, after atomically consuming the token from Redis via `GETDEL`, `auth-service` performs a fast primary-key lookup in PostgreSQL (`SELECT id, roles, is_active FROM users WHERE id = $1`).
* **Why:**
  * Refresh only happens **once every 15 minutes** per active user, and a primary-key lookup in Postgres takes `< 0.5ms`.
  * By checking `users` on refresh:
    1. If an admin promotes/demotes a user's `roles` in PostgreSQL, the new JWT gets the updated roles within 15 minutes (without forcing the user to re-login).
    2. If an admin sets `is_active = false` in PostgreSQL, the user is denied a new JWT at the next refresh.

---

## 6. Cryptographic & Token Specifications

### 6.1 Access Token (JWT) Structure
* **Algorithm:** `EdDSA` (`Ed25519`)
* **Lifetime:** `15 minutes` (`900 seconds`)

**JWT Header:**
```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "key-2026-11"
}
```

**JWT Payload (Claims):**
```json
{
  "iss": "auth-service",
  "sub": "01933b4a-7c80-7000-8000-123456789abc",
  "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "roles": ["USER"],
  "iat": 1794905400,
  "nbf": 1794905400,
  "exp": 1794906300
}
```

### 6.2 Public Key Discovery (`/.well-known/jwks.json`)
Follows **RFC 8037** (`CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)`) for `Ed25519` public keys:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "use": "sig",
      "kid": "key-2026-11",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  ]
}
```
* `x` is the 32-byte `ed25519.PublicKey` encoded in **Base64 RawURL** (`base64.RawURLEncoding`).
* Downstream Go services using `github.com/MicahParks/keyfunc/v3` can parse this endpoint out-of-the-box.

### 6.3 Refresh Token Cookie Specification
```http
Set-Cookie: refresh_token=<43_char_base64url_token>; Path=/api/v1/auth; Max-Age=604800; HttpOnly; Secure; SameSite=Strict
```

> [!WARNING]
> **Critical Cookie `Path` Decision:**  
> Set `Path=/api/v1/auth` (NOT `Path=/api/v1/auth/refresh`).  
> Why? Both `POST /api/v1/auth/refresh` **and** `POST /api/v1/auth/logout` need the browser to send the `refresh_token` cookie so `auth-service` knows which token hash to delete from Redis! Scoping the path to `/api/v1/auth` ensures the cookie is sent to `/refresh` and `/logout`, while never being sent on general API calls to other microservices.

---

## 7. v0.1 MVP API Endpoints Specification

### Standard Error Response Envelope
All error responses across `auth-service` return a consistent JSON structure:
```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password."
  }
}
```

---

### 7.1 `POST /api/v1/auth/register`
Registers a new user account.

* **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "CorrectHorseBatteryStaple!99"
  }
  ```
* **Validation Rules:**
  * `email`: Required, valid RFC 5322 email format, max 254 characters, normalized to lowercase and trimmed.
  * `password`: Required, minimum **8 characters**, maximum **72 characters** (or **128 characters**—bounded to prevent DoS via multi-megabyte password strings fed into Argon2id).
* **Execution Steps:**
  1. Validate input payload.
  2. Generate 16-byte cryptographic salt and compute Argon2id PHC hash (`m=64MB, t=2, p=4`).
  3. Generate `UUIDv7` for user ID.
  4. Insert into PostgreSQL `users` table with default role `['USER']`.
  5. If PostgreSQL returns unique constraint violation (`SQLSTATE 23505` on `uq_users_email`), return `409 Conflict`.
* **Success Response (`201 Created`):**
  ```json
  {
    "user": {
      "id": "01933b4a-7c80-7000-8000-123456789abc",
      "email": "user@example.com",
      "roles": ["USER"],
      "created_at": "2026-11-17T08:50:00Z"
    }
  }
  ```
* **Error Responses:**
  * `400 Bad Request` (`VALIDATION_ERROR`) — Invalid email or password length.
  * `409 Conflict` (`EMAIL_ALREADY_EXISTS`) — Email is already registered.
  * `500 Internal Server Error` (`INTERNAL_ERROR`)

---

### 7.2 `POST /api/v1/auth/login`
Authenticates user credentials and issues an Access JWT + `HttpOnly` Refresh Token cookie.

* **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "CorrectHorseBatteryStaple!99"
  }
  ```
* **Execution Steps:**
  1. Validate input and normalize email.
  2. Query PostgreSQL: `SELECT id, email, password_hash, roles, is_active FROM users WHERE email = $1`.
  3. **Timing-Attack Prevention:** If the email does not exist, run Argon2id verification against a pre-computed dummy hash anyway before returning `401 Unauthorized`. This ensures attackers cannot measure response time (~50ms vs ~1ms) to enumerate registered emails.
  4. Verify password against `user.PasswordHash` using `subtle.ConstantTimeCompare`. If mismatch → `401 Unauthorized`.
  5. Check `user.IsActive`. If `false` → `403 Forbidden` (`ACCOUNT_DISABLED`).
  6. Sign a 15-minute `Ed25519` Access Token JWT (`sub`, `jti`, `roles`, `iss`, `iat`, `exp`).
  7. Generate a 32-byte opaque Refresh Token, compute its SHA-256 hex hash, and store session metadata in Redis (`refresh:<sha256_hash>`) with a 7-day TTL.
  8. Asynchronously or inline update `last_login_at = NOW()` in PostgreSQL.
  9. Attach the raw Refresh Token as an `HttpOnly` cookie and return the Access JWT in the JSON body.
* **Success Response (`200 OK`):**
  * **Header:** `Set-Cookie: refresh_token=<raw_token>; Path=/api/v1/auth; Max-Age=604800; HttpOnly; Secure; SameSite=Strict`
  * **Body:**
    ```json
    {
      "access_token": "eyJhbGciOiJFZERTQSI...",
      "token_type": "Bearer",
      "expires_in": 900,
      "user": {
        "id": "01933b4a-7c80-7000-8000-123456789abc",
        "email": "user@example.com",
        "roles": ["USER"]
      }
    }
    ```
* **Error Responses:**
  * `400 Bad Request` (`VALIDATION_ERROR`)
  * `401 Unauthorized` (`INVALID_CREDENTIALS`)
  * `403 Forbidden` (`ACCOUNT_DISABLED`)

---

### 7.3 `POST /api/v1/auth/refresh`
Rotates the single-use Refresh Token and issues a fresh 15-minute Access JWT + fresh 7-day Refresh Token cookie.

* **Request Input:** Reads `refresh_token` from the `Cookie` header (no JSON body required).
* **Execution Steps:**
  1. Read `refresh_token` cookie. If missing or malformed → return `401 Unauthorized`.
  2. Compute SHA-256 hex hash of the cookie value.
  3. Execute atomic **`GETDEL refresh:<sha256_hash>`** in Redis:
     * If key does not exist (`redis.Nil`) → clear the client cookie and return `401 Unauthorized` (`INVALID_REFRESH_TOKEN`).
     * Because `GETDEL` is atomic, even two concurrent `/refresh` requests arriving at the exact same millisecond cannot both succeed.
  4. Query PostgreSQL (`SELECT id, roles, is_active FROM users WHERE id = $1`):
     * If user not found or `is_active == false` → clear client cookie and return `403 Forbidden`.
  5. Sign a new 15-minute `Ed25519` Access JWT with the user's current `roles`.
  6. Generate a brand-new 32-byte opaque Refresh Token, store its SHA-256 hash in Redis (`TTL: 7 days`), and set the new `HttpOnly` cookie.
* **Success Response (`200 OK`):**
  * **Header:** `Set-Cookie: refresh_token=<new_raw_token>; Path=/api/v1/auth; Max-Age=604800; HttpOnly; Secure; SameSite=Strict`
  * **Body:**
    ```json
    {
      "access_token": "eyJhbGciOiJFZERTQSI...",
      "token_type": "Bearer",
      "expires_in": 900
    }
    ```
* **Error Responses:**
  * `401 Unauthorized` (`INVALID_REFRESH_TOKEN`) — Missing, expired, or already-rotated refresh token.
  * `403 Forbidden` (`ACCOUNT_DISABLED`) — Account was suspended since login.

---

### 7.4 `POST /api/v1/auth/logout`
Revokes the caller's active Refresh Token in Redis and clears the browser cookie.

* **Request Input:** Reads `refresh_token` from the `Cookie` header.
* **Execution Steps:**
  1. If the `refresh_token` cookie is present, compute its SHA-256 hash and execute `DEL refresh:<sha256_hash>` in Redis.
  2. Always overwrite the `refresh_token` cookie with `Max-Age=-1` (empty value) so the browser deletes it immediately.
  3. Return `204 No Content` (idempotent—even if the cookie was already expired or missing).
* **Success Response (`204 No Content`):**
  * **Header:** `Set-Cookie: refresh_token=; Path=/api/v1/auth; Max-Age=-1; HttpOnly; Secure; SameSite=Strict`

---

### 7.5 `GET /.well-known/jwks.json`
Returns the public key set in JWK format for downstream microservices.

* **Execution Steps:**
  1. Served directly from pre-computed in-memory bytes (computed once at startup from `ed25519.PublicKey`).
  2. Sets `Cache-Control: public, max-age=3600` header so downstream verifiers and API gateways can cache it safely.
* **Success Response (`200 OK`):** See Section 6.2.

---

### 7.6 `GET /healthz` & `GET /readyz`
* `GET /healthz` (Liveness): Returns `200 OK` `{"status": "ok"}` immediately if the Go process is alive.
* `GET /readyz` (Readiness): Pings PostgreSQL (`pool.Ping`) and Redis (`client.Ping`) with a 2-second timeout. Returns `200 OK` if both are reachable, or `503 Service Unavailable` if either dependency is down.

---

## 8. Configuration & Environment Variables (v0.1 MVP)

```ini
# Server
APP_ENV=development                          # development | staging | production
HTTP_PORT=8080
HTTP_READ_TIMEOUT=5s
HTTP_WRITE_TIMEOUT=10s

# PostgreSQL
DATABASE_URL=postgres://auth_user:auth_pass@localhost:5432/auth_db?sslmode=disable
DB_MAX_CONNS=25
DB_MIN_CONNS=5

# Redis 8 (No password required)
REDIS_ADDR=localhost:6379
REDIS_DB=0

# Cryptography & Tokens
ED25519_PRIVATE_KEY_BASE64=<base64_encoded_64_byte_ed25519_private_key>
ED25519_KEY_ID=key-2026-11
JWT_ISSUER=auth-service
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=168h                       # 7 days

# Argon2id Parameters
ARGON2_MEMORY_KIB=65536                      # 64 MB
ARGON2_ITERATIONS=2
ARGON2_PARALLELISM=4

# Cookie Settings
COOKIE_SECURE=false                          # true in production (HTTPS), false for localhost HTTP dev
COOKIE_DOMAIN=
```

---

## 9. Finalized Architectural Decisions (v0.1 MVP)

1. **Separate Registration and Login:**
   * `POST /api/v1/auth/register` strictly creates the user record in PostgreSQL and returns `201 Created`. Users then explicitly authenticate via `POST /api/v1/auth/login` to receive their Access JWT and Refresh Cookie.
2. **Web-First (`HttpOnly` Cookie) Refresh Flow:**
   * v0.1 MVP targets web browsers exclusively using `HttpOnly; Secure; SameSite=Strict` cookies for refresh tokens. Mobile/native header/body refresh token support will be added in a subsequent version.
3. **PostgreSQL Stack (`pgx/v5` + `sqlc` + `goose`):**
   * Schema migrations are managed via **Goose** (`pressly/goose/v3`) using single-file `-- +goose Up` / `-- +goose Down` SQL scripts.
   * Database queries are written in annotated SQL and compiled into type-safe Go code via **`sqlc`** backed by **`pgx/v5/pgxpool`**.
4. **Standard Library HTTP Routing (`net/http`):**
   * HTTP routing uses Go 1.22+ standard library `http.ServeMux` (`"POST /api/v1/auth/login"`) with standard `func(http.Handler) http.Handler` middleware composition, keeping zero third-party router dependencies.
