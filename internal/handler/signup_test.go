package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/google/uuid"
)

type fakeSignuper struct {
	res    auth.SignupResult
	err    error
	called bool
	got    auth.SignupInput
}

func (f *fakeSignuper) Signup(_ context.Context, in auth.SignupInput) (auth.SignupResult, error) {
	f.called = true
	f.got = in
	return f.res, f.err
}

const validBody = `{"company_name":"Acme","subdomain":"acme","email":"owner@acme.test","password":"a-long-password"}`

func postSignup(t *testing.T, svc Signuper, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	Signup(svc)(rec, req)
	return rec
}

func TestSignupCreated(t *testing.T) {
	svc := &fakeSignuper{res: auth.SignupResult{
		TenantID: uuid.New(), CompanyName: "Acme", Subdomain: "acme",
		UserID: uuid.New(), Email: "owner@acme.test",
	}}
	rec := postSignup(t, svc, validBody)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	if svc.got.Subdomain != "acme" || svc.got.Email != "owner@acme.test" {
		t.Fatalf("service got %+v", svc.got)
	}
	body := rec.Body.String()
	if strings.Contains(body, "password") {
		t.Fatalf("response must not mention the password: %s", body)
	}
	var resp signupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Tenant.Subdomain != "acme" {
		t.Fatalf("bad response %s (%v)", body, err)
	}
}

func TestSignupRejectsBadInput(t *testing.T) {
	tests := map[string]string{
		"empty body":        ``,
		"not json":          `nope`,
		"unknown field":     `{"company_name":"A","subdomain":"acme","email":"a@b.co","password":"a-long-password","role":"owner"}`,
		"missing company":   `{"subdomain":"acme","email":"a@b.co","password":"a-long-password"}`,
		"bad email":         `{"company_name":"A","subdomain":"acme","email":"nope","password":"a-long-password"}`,
		"short password":    `{"company_name":"A","subdomain":"acme","email":"a@b.co","password":"short"}`,
		"uppercase subdom.": `{"company_name":"A","subdomain":"Acme","email":"a@b.co","password":"a-long-password"}`,
		"underscore subdom": `{"company_name":"A","subdomain":"a_b","email":"a@b.co","password":"a-long-password"}`,
		"reserved subdom.":  `{"company_name":"A","subdomain":"admin","email":"a@b.co","password":"a-long-password"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			svc := &fakeSignuper{}
			rec := postSignup(t, svc, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
			}
			if svc.called {
				t.Fatal("service must not be called for invalid input")
			}
		})
	}
}

func TestSignupValidationFieldNames(t *testing.T) {
	rec := postSignup(t, &fakeSignuper{}, `{"company_name":"","subdomain":"acme","email":"a@b.co","password":"a-long-password"}`)
	if !strings.Contains(rec.Body.String(), `"company_name"`) {
		t.Fatalf("expected JSON field name in error, got %s", rec.Body)
	}
}

func TestSignupBodyTooLarge(t *testing.T) {
	big := `{"company_name":"` + strings.Repeat("x", maxBodyBytes+10) + `"}`
	if rec := postSignup(t, &fakeSignuper{}, big); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSignupServiceErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"subdomain taken", auth.ErrSubdomainTaken, http.StatusConflict, "subdomain_taken"},
		{"email taken", auth.ErrEmailTaken, http.StatusConflict, "email_taken"},
		{"internal", errors.New("pq: connection to 10.0.0.5 refused"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postSignup(t, &fakeSignuper{err: tt.err}, validBody)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if !strings.Contains(rec.Body.String(), tt.code) {
				t.Fatalf("body %s missing code %q", rec.Body, tt.code)
			}
			if strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Fatalf("response leaks internal error: %s", rec.Body)
			}
		})
	}
}
