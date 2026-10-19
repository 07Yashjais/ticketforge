package middleware

import (
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/ratelimit"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// LimitFunc picks the allowance for a caller. Today it can return one flat
// limit; later it will look at the tenant's plan (free, pro, enterprise).
type LimitFunc func(auth.Claims) ratelimit.Limit

// RateLimit throttles requests per tenant. It must run after Authenticate,
// because the bucket is keyed by the tenant ID from the credential: every user
// and API key of one company shares one bucket, so one noisy tenant cannot
// use up capacity that belongs to others.
//
// If the limiter itself fails (for example Redis is down) the request is
// allowed through and the error is logged ("fail open"). A cache outage should
// not take the whole product down.
func RateLimit(l ratelimit.Limiter, limitFor LimitFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				// Programming error: wired before Authenticate. Fail closed.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]string{"code": "internal_error", "message": "something went wrong"},
				})
				return
			}

			limit := limitFor(claims)
			res, err := l.Allow(r.Context(), "tenant:"+claims.TenantID.String(), limit)
			if err != nil {
				slog.Error("rate limiter failed, allowing request", "error", err,
					"tenant_id", claims.TenantID, "request_id", chimw.GetReqID(r.Context()))
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))

			if !res.Allowed {
				// Retry-After is whole seconds, rounded up, at least 1.
				secs := int(math.Ceil(res.RetryAfter.Seconds()))
				if secs < 1 {
					secs = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]string{"code": "rate_limited", "message": "too many requests, slow down"},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
