package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	issuer         = "ticketforge"
	minSecretBytes = 32 // HS256 needs a secret at least as long as its 256-bit hash

	// AccessTokenTTL is short on purpose: a stolen access token stops working
	// quickly. Refresh tokens (see login.go) are what keep a user signed in.
	AccessTokenTTL = 15 * time.Minute
)

// ErrInvalidToken covers every reason an access token is rejected (bad
// signature, expired, wrong algorithm, malformed claims). Callers should not
// tell the client which one.
var ErrInvalidToken = errors.New("invalid access token")

// Claims is what the app knows about the caller once a token is verified.
type Claims struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Role     string

	// APIKeyID is set when the caller authenticated with an API key instead
	// of a user's access token. UserID is then the user who created the key.
	APIKeyID uuid.UUID
}

// IsAPIKey reports whether the caller is a machine using an API key.
func (c Claims) IsAPIKey() bool { return c.APIKeyID != uuid.Nil }

// APIKeyPrefix starts every API key, so a bearer credential can be told
// apart from a JWT without trying to parse it.
const APIKeyPrefix = "tfk_"

// ErrInvalidAPIKey covers unknown, revoked and malformed API keys.
var ErrInvalidAPIKey = errors.New("invalid API key")

// jwtClaims is the wire format inside the token.
type jwtClaims struct {
	TenantID string `json:"tid"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// TokenManager issues and verifies signed access tokens.
type TokenManager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time // replaced in tests
}

// NewTokenManager returns a manager that signs with HS256 using secret.
func NewTokenManager(secret string) (*TokenManager, error) {
	if len(secret) < minSecretBytes {
		return nil, fmt.Errorf("JWT secret must be at least %d bytes", minSecretBytes)
	}
	return &TokenManager{secret: []byte(secret), ttl: AccessTokenTTL, now: time.Now}, nil
}

// Issue signs an access token for the user acting inside the tenant.
func (m *TokenManager) Issue(userID, tenantID uuid.UUID, role string) (string, error) {
	now := m.now()
	claims := jwtClaims{
		TenantID: tenantID.String(),
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return signed, nil
}

// Parse verifies the signature and expiry and returns the caller's claims.
func (m *TokenManager) Parse(token string) (Claims, error) {
	var jc jwtClaims
	_, err := jwt.ParseWithClaims(token, &jc,
		func(*jwt.Token) (any, error) { return m.secret, nil },
		// Pin the algorithm. Without this, a forged token that claims
		// "alg: none" or a different algorithm could slip through.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(m.now),
	)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}

	userID, err := uuid.Parse(jc.Subject)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	tenantID, err := uuid.Parse(jc.TenantID)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	if jc.Role == "" {
		return Claims{}, ErrInvalidToken
	}
	return Claims{UserID: userID, TenantID: tenantID, Role: jc.Role}, nil
}
