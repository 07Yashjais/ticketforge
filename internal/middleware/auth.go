// Package middleware holds HTTP middleware specific to TicketForge.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/07Yashjais/ticketforge/internal/auth"
)

// TokenParser verifies an access token. *auth.TokenManager satisfies it.
type TokenParser interface {
	Parse(token string) (auth.Claims, error)
}

// ctxKey is unexported so no other package can read or overwrite our value.
type ctxKey struct{}

// Authenticate requires a valid "Authorization: Bearer <token>" header and
// stores the caller's claims in the request context.
func Authenticate(parser TokenParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
				unauthorized(w)
				return
			}

			claims, err := parser.Parse(token)
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
