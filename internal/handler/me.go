package handler

import (
	"net/http"

	appmw "github.com/07Yashjais/ticketforge/internal/middleware"
)

// Me returns who the access token says the caller is. It must be mounted
// behind appmw.Authenticate.
func Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := appmw.ClaimsFromContext(r.Context())
	if !ok {
		// Only happens if the route was mounted without Authenticate: a wiring bug.
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid access token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id":   claims.UserID.String(),
		"tenant_id": claims.TenantID.String(),
		"role":      claims.Role,
	})
}
