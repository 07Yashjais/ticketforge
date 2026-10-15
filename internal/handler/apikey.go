package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/07Yashjais/ticketforge/internal/apikey"
	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/db/sqlc"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

// APIKeyService is the API key logic the handlers need.
type APIKeyService interface {
	Create(ctx context.Context, caller auth.Claims, name, role string) (apikey.Created, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]sqlc.ApiKey, error)
	Revoke(ctx context.Context, tenantID, id uuid.UUID) error
}

// APIKeyHandler serves /api-keys. Mount it behind Authenticate and
// RequireRole(admin).
type APIKeyHandler struct {
	svc APIKeyService
}

func NewAPIKeyHandler(svc APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{svc: svc}
}

func (h *APIKeyHandler) Routes(r chi.Router) {
	r.Post("/", h.create)
	r.Get("/", h.list)
	r.Delete("/{id}", h.revoke)
}

type createAPIKeyRequest struct {
	Name string `json:"name" validate:"required,notblank,max=100"`
	Role string `json:"role" validate:"required,oneof=member admin"`
}

type apiKeyResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"` // non-secret hint to tell keys apart
	Role       string     `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func toAPIKeyResponse(k sqlc.ApiKey) apiKeyResponse {
	resp := apiKeyResponse{
		ID: k.ID.String(), Name: k.Name, Prefix: k.Prefix, Role: k.Role, CreatedAt: k.CreatedAt.Time,
	}
	if k.LastUsedAt.Valid {
		resp.LastUsedAt = &k.LastUsedAt.Time
	}
	if k.RevokedAt.Valid {
		resp.RevokedAt = &k.RevokedAt.Time
	}
	return resp // KeyHash is deliberately never included.
}

// humanCaller rejects API-key callers: a key must not be able to mint or
// revoke keys, or one leaked key could create more keys and outlive revocation.
func humanCaller(w http.ResponseWriter, r *http.Request) (auth.Claims, bool) {
	claims, ok := caller(w, r)
	if !ok {
		return auth.Claims{}, false
	}
	if claims.IsAPIKey() {
		writeError(w, http.StatusForbidden, "forbidden", "API keys cannot manage API keys; sign in as a user")
		return auth.Claims{}, false
	}
	return claims, true
}

func (h *APIKeyHandler) create(w http.ResponseWriter, r *http.Request) {
	claims, ok := humanCaller(w, r)
	if !ok {
		return
	}
	var req createAPIKeyRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	created, err := h.svc.Create(r.Context(), claims, req.Name, req.Role)
	if err != nil {
		apiKeyError(w, r, err)
		return
	}

	// The full key exists only in this response. Never cache it.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, struct {
		apiKeyResponse
		Key string `json:"key"`
	}{toAPIKeyResponse(created.Key), created.Secret})
}

func (h *APIKeyHandler) list(w http.ResponseWriter, r *http.Request) {
	claims, ok := humanCaller(w, r)
	if !ok {
		return
	}
	keys, err := h.svc.List(r.Context(), claims.TenantID)
	if err != nil {
		apiKeyError(w, r, err)
		return
	}
	items := make([]apiKeyResponse, 0, len(keys))
	for _, k := range keys {
		items = append(items, toAPIKeyResponse(k))
	}
	writeJSON(w, http.StatusOK, map[string][]apiKeyResponse{"api_keys": items})
}

func (h *APIKeyHandler) revoke(w http.ResponseWriter, r *http.Request) {
	claims, ok := humanCaller(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "API key not found")
		return
	}
	if err := h.svc.Revoke(r.Context(), claims.TenantID, id); err != nil {
		apiKeyError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func apiKeyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, apikey.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "API key not found")
	case errors.Is(err, apikey.ErrRoleNotAllowed):
		writeError(w, http.StatusForbidden, "role_not_allowed", "you cannot create a key with that role")
	default:
		slog.Error("API key request failed", "error", err, "path", r.URL.Path,
			"request_id", middleware.GetReqID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
	}
}
