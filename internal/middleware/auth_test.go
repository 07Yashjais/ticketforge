package middleware

import (
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
			Authenticate(tt.parser)(next).ServeHTTP(rec, req)

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

func TestClaimsFromContextEmpty(t *testing.T) {
	if _, ok := ClaimsFromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok {
		t.Fatal("expected no claims on a bare context")
	}
}
