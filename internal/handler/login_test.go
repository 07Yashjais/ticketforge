package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/07Yashjais/ticketforge/internal/auth"
)

type fakeAuthenticator struct {
	pair      auth.TokenPair
	err       error
	loginIn   auth.LoginInput
	refreshIn string
}

func (f *fakeAuthenticator) Login(_ context.Context, in auth.LoginInput) (auth.TokenPair, error) {
	f.loginIn = in
	return f.pair, f.err
}

func (f *fakeAuthenticator) Refresh(_ context.Context, tok string) (auth.TokenPair, error) {
	f.refreshIn = tok
	return f.pair, f.err
}

func post(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return rec
}

const loginBody = `{"subdomain":"acme","email":"owner@acme.test","password":"whatever"}`

func TestLoginSuccess(t *testing.T) {
	svc := &fakeAuthenticator{pair: auth.TokenPair{AccessToken: "a", RefreshToken: "r", ExpiresIn: 15 * time.Minute}}
	rec := post(Login(svc), loginBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if svc.loginIn.Subdomain != "acme" || svc.loginIn.Email != "owner@acme.test" {
		t.Fatalf("service got %+v", svc.loginIn)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	for _, want := range []string{`"access_token":"a"`, `"refresh_token":"r"`, `"token_type":"Bearer"`, `"expires_in":900`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("body %s missing %s", rec.Body, want)
		}
	}
}

func TestLoginErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"bad credentials", auth.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
		{"suspended", auth.ErrTenantSuspended, http.StatusForbidden, "tenant_suspended"},
		{"internal", errors.New("pq: refused 10.0.0.5"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := post(Login(&fakeAuthenticator{err: tt.err}), loginBody)
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), tt.code) {
				t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, tt.status, tt.code)
			}
			if strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Fatalf("response leaks internal error: %s", rec.Body)
			}
		})
	}
}

func TestLoginRejectsBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         ``,
		"missing email": `{"subdomain":"acme","password":"x"}`,
		"bad email":     `{"subdomain":"acme","email":"nope","password":"x"}`,
		"no password":   `{"subdomain":"acme","email":"a@b.co"}`,
		"unknown field": `{"subdomain":"acme","email":"a@b.co","password":"x","admin":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			svc := &fakeAuthenticator{}
			if rec := post(Login(svc), body); rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if svc.loginIn != (auth.LoginInput{}) {
				t.Fatal("service must not be called for invalid input")
			}
		})
	}
}

func TestRefresh(t *testing.T) {
	svc := &fakeAuthenticator{pair: auth.TokenPair{AccessToken: "a2", RefreshToken: "r2", ExpiresIn: time.Minute}}
	rec := post(Refresh(svc), `{"refresh_token":"abc"}`)
	if rec.Code != http.StatusOK || svc.refreshIn != "abc" {
		t.Fatalf("status = %d, refreshIn = %q", rec.Code, svc.refreshIn)
	}

	rec = post(Refresh(&fakeAuthenticator{err: auth.ErrInvalidRefreshToken}), `{"refresh_token":"abc"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_refresh_token") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}

	if rec := post(Refresh(&fakeAuthenticator{}), `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body status = %d, want 400", rec.Code)
	}
}
