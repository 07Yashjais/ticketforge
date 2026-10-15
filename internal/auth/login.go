package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// RefreshTokenTTL is how long a user stays signed in without logging in again.
const RefreshTokenTTL = 30 * 24 * time.Hour

const tenantStatusActive = "active"

var (
	// ErrInvalidCredentials is deliberately vague: it covers unknown tenant,
	// unknown email, no membership and wrong password alike.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrTenantSuspended is only returned after the password was correct.
	ErrTenantSuspended = errors.New("tenant is suspended")
	// ErrInvalidRefreshToken covers unknown, expired, revoked and reused tokens.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// LoginInput identifies the tenant by subdomain because one user can belong
// to several tenants.
type LoginInput struct {
	Subdomain string
	Email     string
	Password  string
}

// TokenPair is what login and refresh hand back to the client.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration // lifetime of AccessToken
}

// Login checks the credentials and starts a new refresh-token family.
func (s *Service) Login(ctx context.Context, in LoginInput) (TokenPair, error) {
	q := sqlc.New(s.db)

	subdomain := strings.ToLower(strings.TrimSpace(in.Subdomain))
	email := strings.ToLower(strings.TrimSpace(in.Email))

	// tenants and users are global tables, so they can be read without a
	// tenant context. Look everything up first, then verify a password hash no
	// matter what, so a missing account costs the same time as a wrong password.
	tenant, terr := q.GetTenantBySubdomain(ctx, subdomain)
	if terr != nil && !errors.Is(terr, pgx.ErrNoRows) {
		return TokenPair{}, fmt.Errorf("finding tenant: %w", terr)
	}
	user, uerr := q.GetUserByEmail(ctx, email)
	if uerr != nil && !errors.Is(uerr, pgx.ErrNoRows) {
		return TokenPair{}, fmt.Errorf("finding user: %w", uerr)
	}

	hash := s.dummyHash
	found := false
	var membership sqlc.Membership
	if terr == nil && uerr == nil {
		// memberships is protected by RLS, so read it inside a transaction
		// scoped to this tenant.
		merr := db.WithTenantTx(ctx, s.db, tenant.ID, func(tx pgx.Tx) error {
			var err error
			membership, err = sqlc.New(tx).GetMembership(ctx, sqlc.GetMembershipParams{
				TenantID: tenant.ID,
				UserID:   user.ID,
			})
			return err
		})
		switch {
		case merr == nil:
			hash, found = user.PasswordHash, true
		case !errors.Is(merr, pgx.ErrNoRows):
			return TokenPair{}, fmt.Errorf("finding membership: %w", merr)
		}
	}

	ok, verr := VerifyPassword(in.Password, hash)
	if verr != nil {
		return TokenPair{}, fmt.Errorf("verifying password: %w", verr)
	}
	if !found || !ok {
		return TokenPair{}, ErrInvalidCredentials
	}
	if tenant.Status != tenantStatusActive {
		return TokenPair{}, ErrTenantSuspended
	}

	var refresh string
	err := db.WithTenantTx(ctx, s.db, tenant.ID, func(tx pgx.Tx) error {
		var err error
		refresh, err = s.newRefreshToken(ctx, sqlc.New(tx), uuid.New(), user.ID, tenant.ID)
		return err
	})
	if err != nil {
		return TokenPair{}, err
	}
	return s.pair(user.ID, tenant.ID, membership.Role, refresh)
}

// Refresh swaps a valid refresh token for a new access token and a new refresh
// token. The old refresh token stops working (rotation). If an already-used
// token shows up again it was probably stolen, so the whole family is revoked.
func (s *Service) Refresh(ctx context.Context, rawToken string) (TokenPair, error) {
	// The token names its tenant, so we can scope the transaction before the
	// first query. A forged prefix just fails to find a matching hash inside
	// that tenant: RLS hides every other tenant's tokens.
	tenantID, ok := tenantFromRefreshToken(rawToken)
	if !ok {
		return TokenPair{}, ErrInvalidRefreshToken
	}

	var result TokenPair
	// invalid is set instead of returning an error from inside the closure:
	// an error would roll the transaction back, and a family revocation must
	// be committed to have any effect.
	invalid := false

	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		q := sqlc.New(tx)

		rt, err := q.GetRefreshTokenForUpdate(ctx, hashToken(rawToken))
		if errors.Is(err, pgx.ErrNoRows) {
			invalid = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("finding refresh token: %w", err)
		}

		if rt.RevokedAt.Valid {
			// A rotated token came back: treat the family as stolen.
			invalid = true
			return q.RevokeRefreshTokenFamily(ctx, rt.FamilyID)
		}
		if !rt.ExpiresAt.Valid || time.Now().After(rt.ExpiresAt.Time) {
			invalid = true
			return nil
		}

		// Re-check the user's current standing: they may have been removed,
		// demoted, or their tenant suspended since login.
		tenant, err := q.GetTenantByID(ctx, rt.TenantID)
		if err != nil {
			return fmt.Errorf("finding tenant: %w", err)
		}
		membership, err := q.GetMembership(ctx, sqlc.GetMembershipParams{TenantID: rt.TenantID, UserID: rt.UserID})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && tenant.Status != tenantStatusActive) {
			invalid = true
			return q.RevokeRefreshTokenFamily(ctx, rt.FamilyID)
		}
		if err != nil {
			return fmt.Errorf("finding membership: %w", err)
		}

		if err := q.RevokeRefreshToken(ctx, rt.ID); err != nil {
			return fmt.Errorf("revoking old refresh token: %w", err)
		}
		next, err := s.newRefreshToken(ctx, q, rt.FamilyID, rt.UserID, rt.TenantID)
		if err != nil {
			return err
		}
		result, err = s.pair(rt.UserID, rt.TenantID, membership.Role, next)
		return err
	})
	if err != nil {
		return TokenPair{}, err
	}
	if invalid {
		return TokenPair{}, ErrInvalidRefreshToken
	}
	return result, nil
}

// pair builds the response from a fresh refresh token plus a new access token.
func (s *Service) pair(userID, tenantID uuid.UUID, role, refresh string) (TokenPair, error) {
	access, err := s.tokens.Issue(userID, tenantID, role)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: s.tokens.ttl}, nil
}

// newRefreshToken stores a hash of a new token and returns the raw token:
// "<tenant-id>.<256 random bits>". The raw value exists only in the response;
// we cannot recover it later. q must belong to a tenant-scoped transaction.
func (s *Service) newRefreshToken(ctx context.Context, q *sqlc.Queries, family, userID, tenantID uuid.UUID) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating refresh token: %w", err)
	}
	raw := tenantID.String() + "." + base64.RawURLEncoding.EncodeToString(buf)

	_, err := q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		FamilyID:  family,
		UserID:    userID,
		TenantID:  tenantID,
		TokenHash: hashToken(raw),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(RefreshTokenTTL), Valid: true},
	})
	if err != nil {
		return "", fmt.Errorf("storing refresh token: %w", err)
	}
	return raw, nil
}

// tenantFromRefreshToken reads the tenant ID prefix of a refresh token.
func tenantFromRefreshToken(raw string) (uuid.UUID, bool) {
	prefix, _, found := strings.Cut(raw, ".")
	if !found {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(prefix)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// hashToken is SHA-256 rather than argon2: the input is 256 random bits, so
// there is nothing to brute-force, and we need a fast exact-match lookup.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
