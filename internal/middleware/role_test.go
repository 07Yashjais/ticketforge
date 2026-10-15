package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/google/uuid"
)

func TestRequireRole(t *testing.T) {
	tests := []struct {
		name       string
		role       string // "" means no authenticated caller at all
		need       string
		wantStatus int
	}{
		{"no caller", "", auth.RoleMember, http.StatusUnauthorized},
		{"member needs admin", auth.RoleMember, auth.RoleAdmin, http.StatusForbidden},
		{"admin needs owner", auth.RoleAdmin, auth.RoleOwner, http.StatusForbidden},
		{"admin needs admin", auth.RoleAdmin, auth.RoleAdmin, http.StatusOK},
		{"owner needs admin", auth.RoleOwner, auth.RoleAdmin, http.StatusOK},
		{"member needs member", auth.RoleMember, auth.RoleMember, http.StatusOK},
		{"unknown role", "superuser", auth.RoleMember, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

			var h http.Handler = RequireRole(tt.need)(next)
			if tt.role != "" {
				claims := auth.Claims{UserID: uuid.New(), TenantID: uuid.New(), Role: tt.role}
				h = Authenticate(fakeParser{claims: claims}, nil)(h)
			}

			req := httptest.NewRequest(http.MethodDelete, "/x", nil)
			req.Header.Set("Authorization", "Bearer t")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if reached != (tt.wantStatus == http.StatusOK) {
				t.Fatalf("handler reached = %v, want %v", reached, tt.wantStatus == http.StatusOK)
			}
		})
	}
}
