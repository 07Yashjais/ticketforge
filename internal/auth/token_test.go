package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func newTestManager(t *testing.T) *TokenManager {
	t.Helper()
	m, err := NewTokenManager(testSecret)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return m
}

func TestTokenRoundTrip(t *testing.T) {
	m := newTestManager(t)
	uid, tid := uuid.New(), uuid.New()

	tok, err := m.Issue(uid, tid, "admin")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := m.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.UserID != uid || got.TenantID != tid || got.Role != "admin" {
		t.Fatalf("claims = %+v", got)
	}
}

func TestShortSecretRejected(t *testing.T) {
	if _, err := NewTokenManager("too-short"); err == nil {
		t.Fatal("expected an error for a short secret")
	}
}

func TestParseRejectsBadTokens(t *testing.T) {
	m := newTestManager(t)
	uid, tid := uuid.New(), uuid.New()
	valid, _ := m.Issue(uid, tid, "member")

	// Expired: issued long ago.
	old := newTestManager(t)
	old.now = func() time.Time { return time.Now().Add(-2 * AccessTokenTTL) }
	expired, _ := old.Issue(uid, tid, "member")

	// Signed with a different secret.
	other, _ := NewTokenManager("ffffffffffffffffffffffffffffffff")
	wrongKey, _ := other.Issue(uid, tid, "member")

	// Right secret but a different algorithm (HS512) must be refused.
	hs512, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwtClaims{
		TenantID: tid.String(), Role: "owner",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Subject: uid.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString([]byte(testSecret))

	// "alg: none" with no signature at all.
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwtClaims{
		TenantID: tid.String(), Role: "owner",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Subject: uid.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)

	// Payload altered after signing.
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + parts[1] + "A." + parts[2]

	tests := map[string]string{
		"empty":         "",
		"garbage":       "not.a.jwt",
		"expired":       expired,
		"wrong secret":  wrongKey,
		"wrong alg":     hs512,
		"alg none":      none,
		"tampered body": tampered,
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := m.Parse(tok); err != ErrInvalidToken {
				t.Fatalf("Parse error = %v, want ErrInvalidToken", err)
			}
		})
	}
}
