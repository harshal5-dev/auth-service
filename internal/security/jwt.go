package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessTokenClaims struct {
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWTManager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	issuer     string
	accessTTL  time.Duration
	jwksJSON   []byte
}

func NewJWTManager(
	privKey ed25519.PrivateKey,
	pubKey ed25519.PublicKey,
	keyID string,
	issuer string,
	accessTTL time.Duration,
) (*JWTManager, error) {
	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "OKP",
				Crv: "Ed25519",
				Alg: "EdDSA",
				Use: "sig",
				Kid: keyID,
				X:   base64.RawURLEncoding.EncodeToString(pubKey),
			},
		},
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWKS JSON: %w", err)
	}

	return &JWTManager{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      keyID,
		issuer:     issuer,
		accessTTL:  accessTTL,
		jwksJSON:   jwksBytes,
	}, nil
}

func (m *JWTManager) GenerateAccessToken(userID uuid.UUID, roles []string) (string, int64, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(m.accessTTL)

	claims := AccessTokenClaims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = m.keyID

	signedToken, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign EdDSA JWT: %w", err)
	}

	return signedToken, int64(m.accessTTL.Seconds()), nil
}

func (m *JWTManager) JWKSBytes() []byte {
	return m.jwksJSON
}
