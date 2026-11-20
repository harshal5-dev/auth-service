package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	AppEnv           string        `env:"APP_ENV" envDefault:"development"`
	HTTPPort         int           `env:"HTTP_PORT" envDefault:"8080"`
	HTTPReadTimeout  time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"5s"`
	HTTPWriteTimeout time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"10s"`

	// PostgreSQL
	DatabaseURL string `env:"DATABASE_URL,required,notEmpty"`
	DBMaxConns  int32  `env:"DB_MAX_CONNS" envDefault:"25"`
	DBMinConns  int32  `env:"DB_MIN_CONNS" envDefault:"5"`

	// Redis 8 (Passwordless connection)
	RedisAddr string `env:"REDIS_ADDR,required,notEmpty"`
	RedisDB   int    `env:"REDIS_DB" envDefault:"0"`

	// Cryptography & JWT
	Ed25519PrivateKeyBase64 string        `env:"ED25519_PRIVATE_KEY_BASE64,required,notEmpty"`
	Ed25519KeyID            string        `env:"ED25519_KEY_ID" envDefault:"key-2026-11"`
	JWTIssuer               string        `env:"JWT_ISSUER" envDefault:"auth-service"`
	AccessTokenTTL          time.Duration `env:"ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTokenTTL         time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"168h"`

	// Argon2id Parameters
	Argon2MemoryKiB   uint32 `env:"ARGON2_MEMORY_KIB" envDefault:"65536"`
	Argon2Iterations  uint32 `env:"ARGON2_ITERATIONS" envDefault:"2"`
	Argon2Parallelism uint8  `env:"ARGON2_PARALLELISM" envDefault:"4"`

	// Cookie Configuration
	CookieSecure bool   `env:"COOKIE_SECURE" envDefault:"false"`
	CookieDomain string `env:"COOKIE_DOMAIN"`

	// Parsed Cryptographic Keys (populated during Load)
	PrivateKey ed25519.PrivateKey `env:"-"`
	PublicKey  ed25519.PublicKey  `env:"-"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse environment config: %w", err)
	}

	rawKey, err := base64.StdEncoding.DecodeString(cfg.Ed25519PrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in ED25519_PRIVATE_KEY_BASE64: %w", err)
	}

	switch len(rawKey) {
	case ed25519.PrivateKeySize:
		cfg.PrivateKey = ed25519.PrivateKey(rawKey)
	case ed25519.SeedSize:
		cfg.PrivateKey = ed25519.NewKeyFromSeed(rawKey)
	default:
		return nil, fmt.Errorf("invalid Ed25519 private key length: got %d bytes, expected %d or %d",
			len(rawKey), ed25519.SeedSize, ed25519.PrivateKeySize)
	}

	cfg.PublicKey = cfg.PrivateKey.Public().(ed25519.PublicKey)
	return &cfg, nil
}
