package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/apikey"
	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/db/sqlc"
	appmw "github.com/07Yashjais/ticketforge/internal/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type fakeAPIKeys struct {
	err      error
	calls    int
	caller   auth.Claims
	name     string
	role     string
	tenantID uuid.UUID
	id       uuid.UUID
}

func (f *fakeAPIKeys) Create(_ context.Context, caller auth.Claims, name, role string) (apikey.Created, error) {
	f.calls++
	f.caller, f.name, f.role = caller, name, role
	return apikey.Created{
		Key:    sqlc.ApiKey{ID: uuid.New(), Name: name, Role: role, Prefix: "tfk_abcd1234", KeyHash: "SECRET-HASH"},
		Secret: "tfk_full_secret_value",
	}, f.err
}

func (f *fakeAPIKeys) List(_ context.Context, tenantID uuid.UUID) ([]sqlc.ApiKey, error) {
	f.calls++
	f.tenantID = tenantID
	return []sqlc.ApiKey{{ID: uuid.New(), Name: "ci", KeyHash: "SECRET-HASH"}}, f.err
}

func (f *fakeAPIKeys) Revoke(_ context.Context, tenantID, id uuid.UUID) error {
	f.calls++
	f.tenantID, f.id = tenantID, id
	return f.err
}

// Mirrors the production mounting: Authenticate, then RequireRole(admin).
func newAPIKeyRouter(svc APIKeyService, claims auth.Claims) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(appmw.Authenticate(staticParser{claims}, nil))
		r.Use(appmw.RequireRole(auth.RoleAdmin))
		r.Route("/api-keys", NewAPIKeyHandler(svc).Routes)
	})
	return r
}

func adminClaims() auth.Claims {
	return auth.Claims{UserID: uuid.New(), TenantID: uuid.New(), Role: auth.RoleAdmin}
}

func TestCreateAPIKeyReturnsSecretOnce(t *testing.T) {
	claims := adminClaims()
	svc := &fakeAPIKeys{}
	rec := do(newAPIKeyRouter(svc, claims), "POST", "/api-keys", `{"name":"CI","role":"member"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if svc.caller != claims || svc.name != "CI" || svc.role != "member" {
		t.Fatalf("service got caller %+v name %q role %q", svc.caller, svc.name, svc.role)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"key":"tfk_full_secret_value"`) {
		t.Fatalf("create response must include the key once: %s", body)
	}
	if strings.Contains(body, "SECRET-HASH") {
		t.Fatalf("response leaks the key hash: %s", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("key response must not be cacheable")
	}
}

func TestListAPIKeysNeverExposesSecretOrHash(t *testing.T) {
	rec := do(newAPIKeyRouter(&fakeAPIKeys{}, adminClaims()), "GET", "/api-keys", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if b := rec.Body.String(); strings.Contains(b, "SECRET-HASH") || strings.Contains(b, `"key"`) {
		t.Fatalf("list leaks secret material: %s", b)
	}
}

func TestAPIKeyAccessRules(t *testing.T) {
	member := adminClaims()
	member.Role = auth.RoleMember
	machine := adminClaims()
	machine.APIKeyID = uuid.New()

	tests := []struct {
		name   string
		claims auth.Claims
		method string
		path   string
		body   string
		status int
	}{
		{"member cannot create", member, "POST", "/api-keys", `{"name":"x","role":"member"}`, http.StatusForbidden},
		{"member cannot list", member, "GET", "/api-keys", "", http.StatusForbidden},
		{"api key cannot create keys", machine, "POST", "/api-keys", `{"name":"x","role":"member"}`, http.StatusForbidden},
		{"api key cannot list keys", machine, "GET", "/api-keys", "", http.StatusForbidden},
		{"api key cannot revoke keys", machine, "DELETE", "/api-keys/" + uuid.NewString(), "", http.StatusForbidden},
		{"owner role rejected by validation", adminClaims(), "POST", "/api-keys", `{"name":"x","role":"owner"}`, http.StatusBadRequest},
		{"blank name", adminClaims(), "POST", "/api-keys", `{"name":"  ","role":"member"}`, http.StatusBadRequest},
		{"malformed id", adminClaims(), "DELETE", "/api-keys/nope", "", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeAPIKeys{}
			rec := do(newAPIKeyRouter(svc, tt.claims), tt.method, tt.path, tt.body)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.status, rec.Body)
			}
			if svc.calls != 0 {
				t.Fatal("service must not be called")
			}
		})
	}
}

func TestAPIKeyServiceErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"role escalation", apikey.ErrRoleNotAllowed, http.StatusForbidden},
		{"internal", errors.New("db down at 10.0.0.5"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(newAPIKeyRouter(&fakeAPIKeys{err: tt.err}, adminClaims()), "POST", "/api-keys", `{"name":"x","role":"admin"}`)
			if rec.Code != tt.status || strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Fatalf("status = %d (want %d), body %s", rec.Code, tt.status, rec.Body)
			}
		})
	}

	rec := do(newAPIKeyRouter(&fakeAPIKeys{err: apikey.ErrNotFound}, adminClaims()), "DELETE", "/api-keys/"+uuid.NewString(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown key status = %d, want 404", rec.Code)
	}
}
