// Package ticket holds the support-ticket business logic.
//
// Every method takes the tenant ID of the authenticated caller and runs inside
// a tenant-scoped transaction, so Postgres RLS limits it to that tenant's
// rows. A ticket that belongs to another tenant is simply "not found".
package ticket

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/07Yashjais/ticketforge/internal/db"
	"github.com/07Yashjais/ticketforge/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Allowed values, mirrored by CHECK constraints in the migration.
var (
	Statuses   = []string{"open", "in_progress", "resolved", "closed"}
	Priorities = []string{"low", "medium", "high", "urgent"}
)

const (
	defaultPriority = "medium"
	DefaultLimit    = 20
	MaxLimit        = 100
)

var (
	// ErrNotFound means the ticket does not exist for this tenant. It is also
	// what another tenant's ticket looks like, by design.
	ErrNotFound = errors.New("ticket not found")
	// ErrInvalidCursor means a pagination cursor could not be decoded.
	ErrInvalidCursor = errors.New("invalid cursor")
)

// Service implements ticket and comment operations.
type Service struct {
	db db.TxBeginner
}

// NewService returns a Service backed by the given database.
func NewService(conn db.TxBeginner) *Service {
	return &Service{db: conn}
}

type CreateInput struct {
	Title       string
	Description string
	Priority    string // empty means the default
}

// UpdateInput changes only the fields that are non-nil.
type UpdateInput struct {
	Title       *string
	Description *string
	Status      *string
	Priority    *string
}

type ListParams struct {
	Status string // empty means any status
	Limit  int    // 0 means DefaultLimit
	Cursor string // opaque value from a previous ListResult.NextCursor
}

type ListResult struct {
	Tickets    []sqlc.Ticket
	NextCursor string // empty when there are no more pages
}

// Create makes a new ticket for the tenant, authored by userID.
func (s *Service) Create(ctx context.Context, tenantID, userID uuid.UUID, in CreateInput) (sqlc.Ticket, error) {
	priority := in.Priority
	if priority == "" {
		priority = defaultPriority
	}

	var t sqlc.Ticket
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		var err error
		t, err = sqlc.New(tx).CreateTicket(ctx, sqlc.CreateTicketParams{
			TenantID:    tenantID,
			Title:       strings.TrimSpace(in.Title),
			Description: in.Description,
			Priority:    priority,
			CreatedBy:   userID,
		})
		return err
	})
	if err != nil {
		return sqlc.Ticket{}, fmt.Errorf("creating ticket: %w", err)
	}
	return t, nil
}

// Get returns one ticket.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (sqlc.Ticket, error) {
	var t sqlc.Ticket
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		var err error
		t, err = sqlc.New(tx).GetTicket(ctx, id)
		return err
	})
	return t, mapErr("getting ticket", err)
}

// List returns one page of tickets, newest first.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, p ListParams) (ListResult, error) {
	limit := p.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	arg := sqlc.ListTicketsParams{
		Status: pgtype.Text{String: p.Status, Valid: p.Status != ""},
		// Fetch one extra row to learn whether another page exists.
		RowLimit: int32(limit + 1),
	}
	if p.Cursor != "" {
		c, err := decodeCursor(p.Cursor)
		if err != nil {
			return ListResult{}, err
		}
		arg.CursorCreatedAt = pgtype.Timestamptz{Time: c.createdAt, Valid: true}
		arg.CursorID = pgtype.UUID{Bytes: c.id, Valid: true}
	}

	var rows []sqlc.Ticket
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		var err error
		rows, err = sqlc.New(tx).ListTickets(ctx, arg)
		return err
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("listing tickets: %w", err)
	}

	res := ListResult{Tickets: rows}
	if len(rows) > limit {
		res.Tickets = rows[:limit]
		last := res.Tickets[limit-1]
		res.NextCursor = encodeCursor(last.CreatedAt.Time, last.ID)
	}
	return res, nil
}

// Update changes the provided fields of a ticket.
func (s *Service) Update(ctx context.Context, tenantID, id uuid.UUID, in UpdateInput) (sqlc.Ticket, error) {
	var title pgtype.Text
	if in.Title != nil {
		title = pgtype.Text{String: strings.TrimSpace(*in.Title), Valid: true}
	}
	arg := sqlc.UpdateTicketParams{
		ID:          id,
		Title:       title,
		Description: optText(in.Description),
		Status:      optText(in.Status),
		Priority:    optText(in.Priority),
	}

	var t sqlc.Ticket
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		var err error
		t, err = sqlc.New(tx).UpdateTicket(ctx, arg)
		return err
	})
	return t, mapErr("updating ticket", err)
}

// Delete removes a ticket and, by cascade, its comments.
func (s *Service) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	var n int64
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		var err error
		n, err = sqlc.New(tx).DeleteTicket(ctx, id)
		return err
	})
	if err != nil {
		return fmt.Errorf("deleting ticket: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddComment attaches a comment to a ticket the tenant owns.
func (s *Service) AddComment(ctx context.Context, tenantID, userID, ticketID uuid.UUID, body string) (sqlc.Comment, error) {
	var c sqlc.Comment
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		q := sqlc.New(tx)
		// Look the ticket up first so a missing or foreign ticket is a clean
		// "not found" rather than a foreign-key error.
		if _, err := q.GetTicket(ctx, ticketID); err != nil {
			return err
		}
		var err error
		c, err = q.CreateComment(ctx, sqlc.CreateCommentParams{
			TenantID: tenantID,
			TicketID: ticketID,
			AuthorID: userID,
			Body:     strings.TrimSpace(body),
		})
		return err
	})
	return c, mapErr("adding comment", err)
}

// ListComments returns a ticket's comments, oldest first.
func (s *Service) ListComments(ctx context.Context, tenantID, ticketID uuid.UUID) ([]sqlc.Comment, error) {
	var out []sqlc.Comment
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		q := sqlc.New(tx)
		if _, err := q.GetTicket(ctx, ticketID); err != nil {
			return err
		}
		var err error
		out, err = q.ListComments(ctx, ticketID)
		return err
	})
	return out, mapErr("listing comments", err)
}

// mapErr turns "no rows" into ErrNotFound and wraps anything else.
func mapErr(action string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	default:
		return fmt.Errorf("%s: %w", action, err)
	}
}

func optText(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// cursor marks the last ticket of a page.
type cursor struct {
	createdAt time.Time
	id        uuid.UUID
}

// The cursor is opaque to clients (base64) so the format can change later.
func encodeCursor(createdAt time.Time, id uuid.UUID) string {
	raw := createdAt.UTC().Format(time.RFC3339Nano) + "|" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(s string) (cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, ErrInvalidCursor
	}
	tsPart, idPart, ok := strings.Cut(string(raw), "|")
	if !ok {
		return cursor{}, ErrInvalidCursor
	}
	ts, err := time.Parse(time.RFC3339Nano, tsPart)
	if err != nil {
		return cursor{}, ErrInvalidCursor
	}
	id, err := uuid.Parse(idPart)
	if err != nil {
		return cursor{}, ErrInvalidCursor
	}
	return cursor{createdAt: ts, id: id}, nil
}
