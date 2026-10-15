package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/google/uuid"
)

type fakeParser struct {
	claims auth.Claims
	err    error
}

func (f fakeParser) Parse(string) (auth.Claims, error) { return f.claims, f.err }

func TestAuthenticate(t *testing.T) {
	want := auth.Claims{UserID: uuid.New(), TenantID: uuid.New(), Role: "admin"}

	tests := []struct {
		name       string
		header     string
		parser     fakeParser
		wantStatus int
	}{
		{"no header", "", fakeParser{claims: want}, http.StatusUnauthorized},
		{"wrong scheme", "Basic abc", fakeParser{claims: want}, http.StatusUnauthorized},
		{"empty token", "Bearer ", fakeParser{claims: want}, http.StatusUnauthorized},
		{"invalid token", "Bearer abc", fakeParser{err: errors.New("bad")}, http.StatusUnauthorized},
		{"valid token", "Bearer abc", fakeParser{claims: want}, http.StatusOK},
		{"scheme is case-insensitive", "bearer abc", fakeParser{claims: want}, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got auth.Claims
			var reached bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				got, _ = ClaimsFromContext(r.Context())
			})

			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			Authenticate(tt.parser, nil)(next).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK && (!reached || got != want) {
				t.Fatalf("claims in context = %+v (reached=%v), want %+v", got, reached, want)
			}
			if tt.wantStatus == http.StatusUnauthorized && reached {
				t.Fatal("handler must not run for an unauthenticated request")
			}
		})
	}
}

type fakeVerifier struct {
	claims auth.Claims
	err    error
	gotKey string
}

func (f *fakeVerifier) Verify(_ context.Context, key string) (auth.Claims, error) {
	f.gotKey = key
	return f.claims, f.err
}

func TestAuthenticateWithAPIKey(t *testing.T) {
	keyClaims := auth.Claims{UserID: uuid.New(), TenantID: uuid.New(), Role: "member", APIKeyID: uuid.New()}
	jwtClaims := auth.Claims{UserID: uuid.New(), TenantID: uuid.New(), Role: "owner"}
	apiKey := auth.APIKeyPrefix + "abc_def"

	tests := []struct {
		name       string
		credential string
		verifier   *fakeVerifier // nil means API keys are disabled
		wantStatus int
		want       auth.Claims
	}{
		{"valid key", apiKey, &fakeVerifier{claims: keyClaims}, http.StatusOK, keyClaims},
		{"invalid key", apiKey, &fakeVerifier{err: auth.ErrInvalidAPIKey}, http.StatusUnauthorized, auth.Claims{}},
		{"keys disabled", apiKey, nil, http.StatusUnauthorized, auth.Claims{}},
		{"database error", apiKey, &fakeVerifier{err: errors.New("db down")}, http.StatusInternalServerError, auth.Claims{}},
		{"jwt skips verifier", "a.jwt.token", &fakeVerifier{err: errors.New("must not be called")}, http.StatusOK, jwtClaims},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got auth.Claims
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ = ClaimsFromContext(r.Context())
			})

			var keys APIKeyVerifier
			if tt.verifier != nil {
				keys = tt.verifier
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tt.credential)
			rec := httptest.NewRecorder()
			Authenticate(fakeParser{claims: jwtClaims}, keys)(next).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got != tt.want {
				t.Fatalf("claims = %+v, want %+v", got, tt.want)
			}
			if tt.verifier != nil && tt.name == "jwt skips verifier" && tt.verifier.gotKey != "" {
				t.Fatal("a JWT must not be sent to the API key verifier")
			}
		})
	}
}

func TestClaimsFromContextEmpty(t *testing.T) {
	if _, ok := ClaimsFromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok {
		t.Fatal("expected no claims on a bare context")
	}
}
