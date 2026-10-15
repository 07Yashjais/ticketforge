// Package server assembles the HTTP router. It lives outside cmd/api so that
// integration tests can run the exact same routes and middleware as production.
package server

import (
	"net/http"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/handler"
	appmw "github.com/07Yashjais/ticketforge/internal/middleware"
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
}

// NewRouter wires every route.
func NewRouter(d Deps) http.Handler {
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

	// Everything in this group requires a valid access token. The tenant used
	// by the handlers comes from that token.
	r.Group(func(r chi.Router) {
		r.Use(appmw.Authenticate(d.Tokens))
		r.Get("/me", handler.Me)
		r.Route("/tickets", handler.NewTicketHandler(d.Tickets).Routes)
	})

	return r
}
