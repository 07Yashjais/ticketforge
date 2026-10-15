package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/07Yashjais/ticketforge/internal/db"
	"github.com/07Yashjais/ticketforge/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Roles stored in memberships.role.
const roleOwner = "owner"

// Returned when a unique constraint rejects the signup.
var (
	ErrSubdomainTaken = errors.New("subdomain already taken")
	ErrEmailTaken     = errors.New("email already registered")
)

// DB is what the service needs from the database: run queries and start
// transactions. *pgxpool.Pool satisfies it; tests can fake it.
type DB interface {
	sqlc.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Service holds the auth business logic.
type Service struct {
	db     DB
	tokens *TokenManager

	// dummyHash is verified when a login names an unknown account, so unknown
	// and known accounts take about the same time to answer.
	dummyHash string
}

// NewService returns a Service backed by the given database and token manager.
func NewService(conn DB, tokens *TokenManager) (*Service, error) {
	dummy, err := HashPassword("timing-equalizer-not-a-real-password")
	if err != nil {
		return nil, fmt.Errorf("preparing timing hash: %w", err)
	}
	return &Service{db: conn, tokens: tokens, dummyHash: dummy}, nil
}

// SignupInput is validated at the HTTP boundary before it reaches the service.
type SignupInput struct {
	CompanyName string
	Subdomain   string
	Email       string
	Password    string
}

// SignupResult describes what signup created. It never contains the password hash.
type SignupResult struct {
	TenantID    uuid.UUID
	CompanyName string
	Subdomain   string
	UserID      uuid.UUID
	Email       string
}

// Signup creates a tenant, its first user and the Owner membership atomically:
// either all three rows exist afterwards, or none do.
func (s *Service) Signup(ctx context.Context, in SignupInput) (SignupResult, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	subdomain := strings.ToLower(strings.TrimSpace(in.Subdomain))
	name := strings.TrimSpace(in.CompanyName)

	// Hash before opening the transaction: hashing is deliberately slow, and we
	// should not hold a database connection while the CPU works.
	hash, err := HashPassword(in.Password)
	if err != nil {
		return SignupResult{}, fmt.Errorf("hashing password: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return SignupResult{}, fmt.Errorf("beginning transaction: %w", err)
	}
	// After a successful Commit this is a no-op; on any early return it rolls back.
	defer func() { _ = tx.Rollback(ctx) }()

	q := sqlc.New(tx)

	tenant, err := q.CreateTenant(ctx, sqlc.CreateTenantParams{Name: name, Subdomain: subdomain})
	if err != nil {
		return SignupResult{}, fmt.Errorf("creating tenant: %w", mapUniqueViolation(err))
	}

	// From here the transaction acts for the new tenant. memberships is
	// protected by RLS, so its insert is only allowed for this tenant.
	if err := db.SetTenant(ctx, tx, tenant.ID); err != nil {
		return SignupResult{}, err
	}

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		return SignupResult{}, fmt.Errorf("creating user: %w", mapUniqueViolation(err))
	}

	if _, err := q.CreateMembership(ctx, sqlc.CreateMembershipParams{
		TenantID: tenant.ID,
		UserID:   user.ID,
		Role:     roleOwner,
	}); err != nil {
		return SignupResult{}, fmt.Errorf("creating membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return SignupResult{}, fmt.Errorf("committing signup: %w", err)
	}

	return SignupResult{
		TenantID:    tenant.ID,
		CompanyName: tenant.Name,
		Subdomain:   tenant.Subdomain,
		UserID:      user.ID,
		Email:       user.Email,
	}, nil
}

// mapUniqueViolation turns Postgres unique-constraint errors (SQLSTATE 23505)
// into friendly sentinel errors; any other error is returned unchanged.
func mapUniqueViolation(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return err
	}
	switch pgErr.ConstraintName {
	case "tenants_subdomain_key":
		return ErrSubdomainTaken
	case "users_email_lower_key":
		return ErrEmailTaken
	default:
		return err
	}
}
