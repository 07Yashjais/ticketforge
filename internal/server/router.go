// Package server assembles the HTTP router. It lives outside cmd/api so that
// integration tests can run the exact same routes and middleware as production.
package server

import (
	"net/http"

	"github.com/07Yashjais/ticketforge/internal/apikey"
	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/handler"
	appmw "github.com/07Yashjais/ticketforge/internal/middleware"
	"github.com/07Yashjais/ticketforge/internal/ratelimit"
	"github.com/07Yashjais/ticketforge/internal/ticket"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps is everything the router needs.
type Deps struct {
	DB      handler.Pinger
	Auth    *auth.Service
	Tokens  *auth.TokenManager
	Tickets *ticket.Service
	APIKeys *apikey.Service

	// Limiter and LimitFor enable per-tenant rate limiting. If either is nil,
	// limiting is off (tests that are not about limits).
	Limiter  ratelimit.Limiter
	LimitFor appmw.LimitFunc
}

// NewRouter wires every route.
func NewRouter(d Deps) http.Handler {
	// Convert to the interface only when set. A nil *apikey.Service stored in
	// an interface is NOT a nil interface, and the middleware would then try
	// to use it.
	var keys appmw.APIKeyVerifier
	if d.APIKeys != nil {
		keys = d.APIKeys
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	// Public routes.
	r.Get("/health", handler.Health)
	r.Get("/health/ready", handler.Ready(d.DB))
	r.Get("/version", handler.VersionInfo)
	r.Post("/signup", handler.Signup(d.Auth))
	r.Post("/login", handler.Login(d.Auth))
	r.Post("/refresh", handler.Refresh(d.Auth))

	// Everything in this group requires a valid credential: a user's access
	// token or an API key. The tenant used by the handlers comes from it.
	r.Group(func(r chi.Router) {
		r.Use(appmw.Authenticate(d.Tokens, keys))
		if d.Limiter != nil && d.LimitFor != nil {
			r.Use(appmw.RateLimit(d.Limiter, d.LimitFor))
		}
		r.Get("/me", handler.Me)
		r.Route("/tickets", handler.NewTicketHandler(d.Tickets).Routes)

		// Admin-only area.
		r.Group(func(r chi.Router) {
			r.Use(appmw.RequireRole(auth.RoleAdmin))
			r.Route("/api-keys", handler.NewAPIKeyHandler(d.APIKeys).Routes)
		})
	})

	return r
}
