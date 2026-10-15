package apikey

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/google/uuid"
)

func TestKeyFormatRoundTrip(t *testing.T) {
	tenant := uuid.New()
	for i := 0; i < 200; i++ { // many random secrets, some will contain "_"
		secret, err := randomSecret()
		if err != nil {
			t.Fatalf("randomSecret: %v", err)
		}
		raw := formatKey(tenant, secret)
		if !strings.HasPrefix(raw, auth.APIKeyPrefix) {
			t.Fatalf("key %q lacks prefix", raw)
		}
		got, ok := parseKey(raw)
		if !ok || got != tenant {
			t.Fatalf("parseKey(%q) = %v, %v; want %v", raw, got, ok, tenant)
		}
	}
}

func TestParseKeyRejectsMalformed(t *testing.T) {
	good := formatKey(uuid.New(), "secret")
	for _, bad := range []string{
		"",
		"secret",
		"tfk_",
		"tfk_nothex_abc",
		"tfk_" + strings.Repeat("a", 31) + "_abc", // tenant part too short
		"tfk_" + strings.Repeat("z", 32) + "_abc", // not hex
		strings.TrimSuffix(good, "secret"),        // no secret
		"xyz_" + strings.TrimPrefix(good, "tfk_"), // wrong prefix
	} {
		if _, ok := parseKey(bad); ok {
			t.Errorf("parseKey(%q) accepted a malformed key", bad)
		}
	}
}

// Role rules are checked before any database access, so a nil database is fine.
func TestCreateRejectsDisallowedRoles(t *testing.T) {
	svc := NewService(nil)
	tests := []struct {
		name, callerRole, keyRole string
	}{
		{"owner keys are never allowed", auth.RoleOwner, auth.RoleOwner},
		{"member cannot mint admin key", auth.RoleMember, auth.RoleAdmin},
		{"unknown role", auth.RoleOwner, "root"},
		{"empty role", auth.RoleOwner, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := auth.Claims{UserID: uuid.New(), TenantID: uuid.New(), Role: tt.callerRole}
			if _, err := svc.Create(context.Background(), caller, "k", tt.keyRole); !errors.Is(err, ErrRoleNotAllowed) {
				t.Fatalf("error = %v, want ErrRoleNotAllowed", err)
			}
		})
	}
}

func TestVerifyRejectsMalformedWithoutDatabase(t *testing.T) {
	if _, err := NewService(nil).Verify(context.Background(), "tfk_garbage"); !errors.Is(err, auth.ErrInvalidAPIKey) {
		t.Fatalf("error = %v, want ErrInvalidAPIKey", err)
	}
}
