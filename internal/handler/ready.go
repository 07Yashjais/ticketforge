package handler

import (
	"context"
	"net/http"
	"time"
)

// Pinger is anything that can check its own connectivity (a pgx pool does).
// It is defined here, where it is used, so tests can supply a fake.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Ready reports whether the app can serve traffic, i.e. the database answers.
// Unlike Health (process is alive), failing this should stop traffic routing.
func Ready(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := db.Ping(ctx); err != nil {
			// Do not leak the underlying error (it can contain host details).
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}
