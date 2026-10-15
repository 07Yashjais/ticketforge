//go:build integration

package test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/apikey"
	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/server"
	"github.com/07Yashjais/ticketforge/internal/ticket"
	"github.com/google/uuid"
)

const (
	testPassword  = "a-long-test-password"
	testJWTSecret = "0123456789abcdef0123456789abcdef"
)

func newAuthService(t *testing.T) *auth.Service {
	t.Helper()
	tokens, err := auth.NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("token manager: %v", err)
	}
	svc, err := auth.NewService(appPool, tokens)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}
	return svc
}

// testServer runs the real router (same routes and middleware as production)
// on top of the restricted-role database pool.
type testServer struct {
	*httptest.Server
	auth *auth.Service
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	tokens, err := auth.NewTokenManager(testJWTSecret)
	if err != nil {
		t.Fatalf("token manager: %v", err)
	}
	authSvc := newAuthService(t)
	srv := httptest.NewServer(server.NewRouter(server.Deps{
		DB:      appPool,
		Auth:    authSvc,
		Tokens:  tokens,
		Tickets: ticket.NewService(appPool),
		APIKeys: apikey.NewService(appPool),
	}))
	t.Cleanup(srv.Close)
	return &testServer{Server: srv, auth: authSvc}
}

// tenantUser is a signed-up tenant owner plus a ready-to-use access token.
type tenantUser struct {
	auth.SignupResult
	Token string
}

func (s *testServer) newTenant(t *testing.T, label string) tenantUser {
	t.Helper()
	res := signupTenant(t, s.auth, label)
	pair, err := s.auth.Login(testCtx(t), auth.LoginInput{Subdomain: res.Subdomain, Email: res.Email, Password: testPassword})
	if err != nil {
		t.Fatalf("login %s: %v", label, err)
	}
	return tenantUser{SignupResult: res, Token: pair.AccessToken}
}

// addUser creates another user in tenant t with the given role and logs them
// in. Invitations don't exist yet, so the rows are seeded as the owner role.
func (s *testServer) addUser(t *testing.T, tenant tenantUser, role string) tenantUser {
	t.Helper()
	ctx := testCtx(t)
	email := role + "-" + unique(t) + "@" + tenant.Subdomain + ".test"

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	var userID uuid.UUID
	if err := ownerPool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`, email, hash).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := ownerPool.Exec(ctx,
		`INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, $3)`, tenant.TenantID, userID, role); err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	pair, err := s.auth.Login(ctx, auth.LoginInput{Subdomain: tenant.Subdomain, Email: email, Password: testPassword})
	if err != nil {
		t.Fatalf("login %s: %v", role, err)
	}
	u := tenant
	u.UserID, u.Email, u.Token = userID, email, pair.AccessToken
	return u
}

// call sends a JSON request and returns the status and decoded JSON body
// (nil for an empty body). Pass token "" for an unauthenticated call.
func (s *testServer) call(t *testing.T, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(testCtx(t), method, s.URL+path, rdr)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: bad JSON %q: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode, out
}

// mustCall is call plus an expected status code.
func (s *testServer) mustCall(t *testing.T, want int, token, method, path string, body any) map[string]any {
	t.Helper()
	code, out := s.call(t, token, method, path, body)
	if code != want {
		t.Fatalf("%s %s = %d, want %d; body %v", method, path, code, want, out)
	}
	return out
}

// unique returns a short random suffix so tests sharing one database never
// collide on subdomains or emails.
func unique(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return hex.EncodeToString(b)
}

// signupTenant creates a tenant with an owner through the real signup path,
// connected as the restricted app role (so RLS applies to signup itself).
func signupTenant(t *testing.T, svc *auth.Service, label string) auth.SignupResult {
	t.Helper()
	id := label + unique(t)
	res, err := svc.Signup(testCtx(t), auth.SignupInput{
		CompanyName: "Company " + id,
		Subdomain:   id,
		Email:       "owner@" + id + ".test",
		Password:    testPassword,
	})
	if err != nil {
		t.Fatalf("signup %s: %v", id, err)
	}
	return res
}
