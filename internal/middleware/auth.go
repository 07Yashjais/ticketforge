// Package middleware holds HTTP middleware specific to TicketForge.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/07Yashjais/ticketforge/internal/auth"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// TokenParser verifies an access token. *auth.TokenManager satisfies it.
type TokenParser interface {
	Parse(token string) (auth.Claims, error)
}

// APIKeyVerifier checks an API key against the database.
type APIKeyVerifier interface {
	Verify(ctx context.Context, key string) (auth.Claims, error)
}

// ctxKey is unexported so no other package can read or overwrite our value.
type ctxKey struct{}

// Authenticate requires "Authorization: Bearer <credential>", where the
// credential is either a user's JWT access token or an API key (which starts
// with auth.APIKeyPrefix). It stores the caller's claims in the request
// context. keys may be nil, in which case API keys are refused.
func Authenticate(tokens TokenParser, keys APIKeyVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
				unauthorized(w)
				return
			}

			var claims auth.Claims
			var err error
			if strings.HasPrefix(token, auth.APIKeyPrefix) {
				if keys == nil {
					unauthorized(w)
					return
				}
				claims, err = keys.Verify(r.Context(), token)
				// A database failure is our problem (500), not a bad key (401).
				if err != nil && !errors.Is(err, auth.ErrInvalidAPIKey) {
					slog.Error("verifying API key", "error", err, "request_id", chimw.GetReqID(r.Context()))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error": map[string]string{"code": "internal_error", "message": "something went wrong"},
					})
					return
				}
			} else {
				claims, err = tokens.Parse(token)
			}
			if err != nil {
				unauthorized(w)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext returns the authenticated caller, if Authenticate ran.
func ClaimsFromContext(ctx context.Context) (auth.Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(auth.Claims)
	return c, ok
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": "unauthorized", "message": "missing or invalid access token"},
	})
}
