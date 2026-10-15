package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/db/sqlc"
	appmw "github.com/07Yashjais/ticketforge/internal/middleware"
	"github.com/07Yashjais/ticketforge/internal/ticket"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type fakeTickets struct {
	err error

	// What the handler passed in.
	tenantID  uuid.UUID
	userID    uuid.UUID
	id        uuid.UUID
	createIn  ticket.CreateInput
	updateIn  ticket.UpdateInput
	listIn    ticket.ListParams
	commentIn string
	calls     int
}

func (f *fakeTickets) Create(_ context.Context, tenantID, userID uuid.UUID, in ticket.CreateInput) (sqlc.Ticket, error) {
	f.calls++
	f.tenantID, f.userID, f.createIn = tenantID, userID, in
	return sqlc.Ticket{ID: uuid.New(), Title: in.Title}, f.err
}

func (f *fakeTickets) Get(_ context.Context, tenantID, id uuid.UUID) (sqlc.Ticket, error) {
	f.calls++
	f.tenantID, f.id = tenantID, id
	return sqlc.Ticket{ID: id}, f.err
}

func (f *fakeTickets) List(_ context.Context, tenantID uuid.UUID, p ticket.ListParams) (ticket.ListResult, error) {
	f.calls++
	f.tenantID, f.listIn = tenantID, p
	return ticket.ListResult{Tickets: []sqlc.Ticket{{ID: uuid.New()}}, NextCursor: "next"}, f.err
}

func (f *fakeTickets) Update(_ context.Context, tenantID, id uuid.UUID, in ticket.UpdateInput) (sqlc.Ticket, error) {
	f.calls++
	f.tenantID, f.id, f.updateIn = tenantID, id, in
	return sqlc.Ticket{ID: id}, f.err
}

func (f *fakeTickets) Delete(_ context.Context, tenantID, id uuid.UUID) error {
	f.calls++
	f.tenantID, f.id = tenantID, id
	return f.err
}

func (f *fakeTickets) AddComment(_ context.Context, tenantID, userID, ticketID uuid.UUID, body string) (sqlc.Comment, error) {
	f.calls++
	f.tenantID, f.userID, f.id, f.commentIn = tenantID, userID, ticketID, body
	return sqlc.Comment{ID: uuid.New(), TicketID: ticketID}, f.err
}

func (f *fakeTickets) ListComments(_ context.Context, tenantID, ticketID uuid.UUID) ([]sqlc.Comment, error) {
	f.calls++
	f.tenantID, f.id = tenantID, ticketID
	return nil, f.err
}

type staticParser struct{ claims auth.Claims }

func (p staticParser) Parse(string) (auth.Claims, error) { return p.claims, nil }

// newTicketRouter mounts the real routes behind the real Authenticate middleware.
func newTicketRouter(svc TicketService, claims auth.Claims) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(appmw.Authenticate(staticParser{claims}, nil))
		r.Route("/tickets", NewTicketHandler(svc).Routes)
	})
	return r
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func testClaims() auth.Claims {
	return auth.Claims{UserID: uuid.New(), TenantID: uuid.New(), Role: "member"}
}

func TestTicketsRequireAuthentication(t *testing.T) {
	svc := &fakeTickets{}
	h := newTicketRouter(svc, testClaims())
	id := uuid.NewString()

	for _, rt := range []struct{ method, path string }{
		{"POST", "/tickets"}, {"GET", "/tickets"}, {"GET", "/tickets/" + id},
		{"PATCH", "/tickets/" + id}, {"DELETE", "/tickets/" + id},
		{"POST", "/tickets/" + id + "/comments"}, {"GET", "/tickets/" + id + "/comments"},
	} {
		req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{}`)) // no Authorization header
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token: status %d, want 401", rt.method, rt.path, rec.Code)
		}
	}
	if svc.calls != 0 {
		t.Fatalf("service was called %d times for unauthenticated requests", svc.calls)
	}
}

func TestCreateUsesTenantFromToken(t *testing.T) {
	claims := testClaims()
	svc := &fakeTickets{}
	other := uuid.New()

	rec := do(newTicketRouter(svc, claims), "POST", "/tickets", `{"title":"  Printer broken ","priority":"high"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if svc.tenantID != claims.TenantID || svc.userID != claims.UserID {
		t.Fatalf("service got tenant %s user %s, want the token's %s / %s", svc.tenantID, svc.userID, claims.TenantID, claims.UserID)
	}

	// A client cannot name a tenant: the field is simply not accepted.
	svc.calls = 0
	rec = do(newTicketRouter(svc, claims), "POST", "/tickets", `{"title":"x","tenant_id":"`+other.String()+`"}`)
	if rec.Code != http.StatusBadRequest || svc.calls != 0 {
		t.Fatalf("tenant_id in body: status %d, calls %d; want 400 and no service call", rec.Code, svc.calls)
	}
}

func TestTicketValidation(t *testing.T) {
	id := uuid.NewString()
	tests := []struct{ name, method, path, body string }{
		{"missing title", "POST", "/tickets", `{"description":"x"}`},
		{"blank title", "POST", "/tickets", `{"title":"   "}`},
		{"title too long", "POST", "/tickets", `{"title":"` + strings.Repeat("a", 201) + `"}`},
		{"bad priority", "POST", "/tickets", `{"title":"x","priority":"asap"}`},
		{"unknown field", "POST", "/tickets", `{"title":"x","admin":true}`},
		{"empty patch", "PATCH", "/tickets/" + id, `{}`},
		{"bad status", "PATCH", "/tickets/" + id, `{"status":"done"}`},
		{"blank title patch", "PATCH", "/tickets/" + id, `{"title":" "}`},
		{"blank comment", "POST", "/tickets/" + id + "/comments", `{"body":"  "}`},
		{"missing comment body", "POST", "/tickets/" + id + "/comments", `{}`},
		{"bad list status", "GET", "/tickets?status=nope", ``},
		{"limit zero", "GET", "/tickets?limit=0", ``},
		{"limit too big", "GET", "/tickets?limit=101", ``},
		{"limit not a number", "GET", "/tickets?limit=abc", ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeTickets{}
			rec := do(newTicketRouter(svc, testClaims()), tt.method, tt.path, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
			}
			if svc.calls != 0 {
				t.Fatal("service must not be called for invalid input")
			}
		})
	}
}

func TestMalformedIDIsNotFound(t *testing.T) {
	svc := &fakeTickets{}
	rec := do(newTicketRouter(svc, testClaims()), "GET", "/tickets/not-a-uuid", "")
	if rec.Code != http.StatusNotFound || svc.calls != 0 {
		t.Fatalf("status %d, calls %d; want 404 and no service call", rec.Code, svc.calls)
	}
}

func TestListPassesParameters(t *testing.T) {
	claims := testClaims()
	svc := &fakeTickets{}
	rec := do(newTicketRouter(svc, claims), "GET", "/tickets?status=open&limit=5&cursor=abc", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if svc.listIn != (ticket.ListParams{Status: "open", Limit: 5, Cursor: "abc"}) || svc.tenantID != claims.TenantID {
		t.Fatalf("service got %+v for tenant %s", svc.listIn, svc.tenantID)
	}
	if !strings.Contains(rec.Body.String(), `"next_cursor":"next"`) {
		t.Fatalf("body %s missing next_cursor", rec.Body)
	}
}

func TestTicketServiceErrors(t *testing.T) {
	id := uuid.NewString()
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"not found", ticket.ErrNotFound, http.StatusNotFound},
		{"bad cursor", ticket.ErrInvalidCursor, http.StatusBadRequest},
		{"internal", errors.New("pq: refused 10.0.0.5"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(newTicketRouter(&fakeTickets{err: tt.err}, testClaims()), "GET", "/tickets/"+id, "")
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Fatalf("response leaks internal error: %s", rec.Body)
			}
		})
	}
}

func TestDeleteReturnsNoContent(t *testing.T) {
	svc := &fakeTickets{}
	id := uuid.New()
	rec := do(newTicketRouter(svc, testClaims()), "DELETE", "/tickets/"+id.String(), "")
	if rec.Code != http.StatusNoContent || svc.id != id {
		t.Fatalf("status %d, id %s", rec.Code, svc.id)
	}
}

func TestCommentUsesTokenUser(t *testing.T) {
	claims := testClaims()
	svc := &fakeTickets{}
	id := uuid.New()
	rec := do(newTicketRouter(svc, claims), "POST", "/tickets/"+id.String()+"/comments", `{"body":"hello"}`)
	if rec.Code != http.StatusCreated || svc.userID != claims.UserID || svc.tenantID != claims.TenantID || svc.id != id {
		t.Fatalf("status %d; service got tenant %s user %s ticket %s", rec.Code, svc.tenantID, svc.userID, svc.id)
	}
}
