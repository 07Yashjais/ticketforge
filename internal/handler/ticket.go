package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/db/sqlc"
	appmw "github.com/07Yashjais/ticketforge/internal/middleware"
	"github.com/07Yashjais/ticketforge/internal/ticket"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

// TicketService is the ticket logic the handlers need. Defined here, where it
// is used, so tests can supply a fake.
type TicketService interface {
	Create(ctx context.Context, tenantID, userID uuid.UUID, in ticket.CreateInput) (sqlc.Ticket, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (sqlc.Ticket, error)
	List(ctx context.Context, tenantID uuid.UUID, p ticket.ListParams) (ticket.ListResult, error)
	Update(ctx context.Context, tenantID, id uuid.UUID, in ticket.UpdateInput) (sqlc.Ticket, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
	AddComment(ctx context.Context, tenantID, userID, ticketID uuid.UUID, body string) (sqlc.Comment, error)
	ListComments(ctx context.Context, tenantID, ticketID uuid.UUID) ([]sqlc.Comment, error)
}

// TicketHandler serves the /tickets endpoints. The tenant and user always come
// from the verified access token, never from the URL or request body.
type TicketHandler struct {
	svc TicketService
}

func NewTicketHandler(svc TicketService) *TicketHandler {
	return &TicketHandler{svc: svc}
}

// Routes mounts the ticket endpoints. Mount it behind appmw.Authenticate.
func (h *TicketHandler) Routes(r chi.Router) {
	r.Post("/", h.create)
	r.Get("/", h.list)
	r.Route("/{id}", func(r chi.Router) {
		r.Get("/", h.get)
		r.Patch("/", h.update)
		// Deleting is destructive and irreversible: admins and owners only.
		r.With(appmw.RequireRole(auth.RoleAdmin)).Delete("/", h.delete)
		r.Post("/comments", h.addComment)
		r.Get("/comments", h.listComments)
	})
}

type createTicketRequest struct {
	Title       string `json:"title"       validate:"required,notblank,max=200"`
	Description string `json:"description" validate:"max=10000"`
	Priority    string `json:"priority"    validate:"omitempty,oneof=low medium high urgent"`
}

type updateTicketRequest struct {
	Title       *string `json:"title"       validate:"omitempty,notblank,max=200"`
	Description *string `json:"description" validate:"omitempty,max=10000"`
	Status      *string `json:"status"      validate:"omitempty,oneof=open in_progress resolved closed"`
	Priority    *string `json:"priority"    validate:"omitempty,oneof=low medium high urgent"`
}

type commentRequest struct {
	Body string `json:"body" validate:"required,notblank,max=10000"`
}

type ticketResponse struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Priority    string    `json:"priority"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type commentResponse struct {
	ID        string    `json:"id"`
	TicketID  string    `json:"ticket_id"`
	AuthorID  string    `json:"author_id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

func toTicketResponse(t sqlc.Ticket) ticketResponse {
	return ticketResponse{
		ID: t.ID.String(), Title: t.Title, Description: t.Description,
		Status: t.Status, Priority: t.Priority, CreatedBy: t.CreatedBy.String(),
		CreatedAt: t.CreatedAt.Time, UpdatedAt: t.UpdatedAt.Time,
	}
}

func toCommentResponse(c sqlc.Comment) commentResponse {
	return commentResponse{
		ID: c.ID.String(), TicketID: c.TicketID.String(), AuthorID: c.AuthorID.String(),
		Body: c.Body, CreatedAt: c.CreatedAt.Time,
	}
}

func (h *TicketHandler) create(w http.ResponseWriter, r *http.Request) {
	claims, ok := caller(w, r)
	if !ok {
		return
	}
	var req createTicketRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}
	t, err := h.svc.Create(r.Context(), claims.TenantID, claims.UserID, ticket.CreateInput{
		Title: req.Title, Description: req.Description, Priority: req.Priority,
	})
	if err != nil {
		ticketError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toTicketResponse(t))
}

func (h *TicketHandler) list(w http.ResponseWriter, r *http.Request) {
	claims, ok := caller(w, r)
	if !ok {
		return
	}

	q := r.URL.Query()
	params := ticket.ListParams{Status: q.Get("status"), Cursor: q.Get("cursor")}
	if params.Status != "" && !contains(ticket.Statuses, params.Status) {
		writeValidationError(w, map[string]string{"status": "must be one of: open in_progress resolved closed"})
		return
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > ticket.MaxLimit {
			writeValidationError(w, map[string]string{"limit": "must be a number between 1 and " + strconv.Itoa(ticket.MaxLimit)})
			return
		}
		params.Limit = n
	}

	res, err := h.svc.List(r.Context(), claims.TenantID, params)
	if err != nil {
		ticketError(w, r, err)
		return
	}

	items := make([]ticketResponse, 0, len(res.Tickets))
	for _, t := range res.Tickets {
		items = append(items, toTicketResponse(t))
	}
	writeJSON(w, http.StatusOK, struct {
		Tickets    []ticketResponse `json:"tickets"`
		NextCursor string           `json:"next_cursor,omitempty"`
	}{items, res.NextCursor})
}

func (h *TicketHandler) get(w http.ResponseWriter, r *http.Request) {
	claims, id, ok := callerAndID(w, r)
	if !ok {
		return
	}
	t, err := h.svc.Get(r.Context(), claims.TenantID, id)
	if err != nil {
		ticketError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTicketResponse(t))
}

func (h *TicketHandler) update(w http.ResponseWriter, r *http.Request) {
	claims, id, ok := callerAndID(w, r)
	if !ok {
		return
	}
	var req updateTicketRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}
	if req.Title == nil && req.Description == nil && req.Status == nil && req.Priority == nil {
		writeError(w, http.StatusBadRequest, "empty_update", "provide at least one field to change")
		return
	}
	t, err := h.svc.Update(r.Context(), claims.TenantID, id, ticket.UpdateInput{
		Title: req.Title, Description: req.Description, Status: req.Status, Priority: req.Priority,
	})
	if err != nil {
		ticketError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTicketResponse(t))
}

func (h *TicketHandler) delete(w http.ResponseWriter, r *http.Request) {
	claims, id, ok := callerAndID(w, r)
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), claims.TenantID, id); err != nil {
		ticketError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *TicketHandler) addComment(w http.ResponseWriter, r *http.Request) {
	claims, id, ok := callerAndID(w, r)
	if !ok {
		return
	}
	var req commentRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}
	c, err := h.svc.AddComment(r.Context(), claims.TenantID, claims.UserID, id, req.Body)
	if err != nil {
		ticketError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCommentResponse(c))
}

func (h *TicketHandler) listComments(w http.ResponseWriter, r *http.Request) {
	claims, id, ok := callerAndID(w, r)
	if !ok {
		return
	}
	cs, err := h.svc.ListComments(r.Context(), claims.TenantID, id)
	if err != nil {
		ticketError(w, r, err)
		return
	}
	items := make([]commentResponse, 0, len(cs))
	for _, c := range cs {
		items = append(items, toCommentResponse(c))
	}
	writeJSON(w, http.StatusOK, map[string][]commentResponse{"comments": items})
}

// caller returns the authenticated claims set by appmw.Authenticate.
func caller(w http.ResponseWriter, r *http.Request) (auth.Claims, bool) {
	claims, ok := appmw.ClaimsFromContext(r.Context())
	if !ok {
		// Only happens if a route was mounted without Authenticate: a wiring bug.
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid access token")
	}
	return claims, ok
}

// callerAndID also parses the {id} URL parameter. A malformed ID is reported
// as "not found", the same as an ID that does not exist.
func callerAndID(w http.ResponseWriter, r *http.Request) (auth.Claims, uuid.UUID, bool) {
	claims, ok := caller(w, r)
	if !ok {
		return auth.Claims{}, uuid.Nil, false
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "ticket not found")
		return auth.Claims{}, uuid.Nil, false
	}
	return claims, id, true
}

func ticketError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ticket.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "ticket not found")
	case errors.Is(err, ticket.ErrInvalidCursor):
		writeValidationError(w, map[string]string{"cursor": "is invalid"})
	default:
		slog.Error("ticket request failed", "error", err, "path", r.URL.Path,
			"request_id", middleware.GetReqID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
