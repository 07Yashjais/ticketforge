package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/07Yashjais/ticketforge/internal/auth"
)

// RequireRole lets the request through only if the authenticated caller holds
// at least the given role. It must run after Authenticate.
//
// 401 means "we don't know who you are"; 403 means "we know, and you may not".
func RequireRole(min string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				unauthorized(w)
				return
			}
			if !auth.HasRole(claims.Role, min) {
				forbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": "forbidden", "message": "your role does not allow this action"},
	})
}
