package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/go-chi/chi/v5/middleware"
)

// Authenticator signs users in and renews their sessions. Defined here, where
// it is used, so tests can supply a fake.
type Authenticator interface {
	Login(ctx context.Context, in auth.LoginInput) (auth.TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (auth.TokenPair, error)
}

type loginRequest struct {
	Subdomain string `json:"subdomain" validate:"required,max=63"`
	Email     string `json:"email"     validate:"required,email,max=254"`
	// No minimum length here: login should not reveal the password policy.
	Password string `json:"password"  validate:"required,max=128"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,max=256"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds until access_token expires
}

func writeTokens(w http.ResponseWriter, p auth.TokenPair) {
	// Tokens must never be cached by browsers or proxies.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  p.AccessToken,
		RefreshToken: p.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(p.ExpiresIn.Seconds()),
	})
}

// Login handles POST /login.
func Login(svc Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if !decodeAndValidate(w, r, &req) {
			return
		}

		pair, err := svc.Login(r.Context(), auth.LoginInput{
			Subdomain: req.Subdomain,
			Email:     req.Email,
			Password:  req.Password,
		})
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "email, password or company is incorrect")
		case errors.Is(err, auth.ErrTenantSuspended):
			writeError(w, http.StatusForbidden, "tenant_suspended", "this account is suspended")
		case err != nil:
			slog.Error("login failed", "error", err, "request_id", middleware.GetReqID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		default:
			writeTokens(w, pair)
		}
	}
}

// Refresh handles POST /refresh.
func Refresh(svc Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if !decodeAndValidate(w, r, &req) {
			return
		}

		pair, err := svc.Refresh(r.Context(), req.RefreshToken)
		switch {
		case errors.Is(err, auth.ErrInvalidRefreshToken):
			writeError(w, http.StatusUnauthorized, "invalid_refresh_token", "refresh token is invalid or expired")
		case err != nil:
			slog.Error("refresh failed", "error", err, "request_id", middleware.GetReqID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		default:
			writeTokens(w, pair)
		}
	}
}
