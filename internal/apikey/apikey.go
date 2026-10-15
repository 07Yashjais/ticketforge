// Package apikey manages per-tenant API keys for machine-to-machine access.
//
// Key format:  tfk_<tenant id as 32 hex chars>_<256 random bits, base64url>
//
// The tenant ID is readable so the key can be verified inside a transaction
// scoped to that tenant (Row-Level Security hides every other tenant's keys).
// A forged tenant part simply finds no matching hash. Only a SHA-256 hash of
// the key is stored; the full key is returned exactly once, at creation.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/db"
	"github.com/07Yashjais/ticketforge/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const hintLen = 8 // characters of the secret kept as a non-secret hint

var (
	ErrNotFound = errors.New("API key not found")
	// ErrRoleNotAllowed means the requested key role is invalid, is "owner",
	// or is higher than the role of the person creating the key.
	ErrRoleNotAllowed = errors.New("role not allowed for API key")
)

// Service creates, lists, revokes and verifies API keys.
type Service struct {
	db db.TxBeginner
}

func NewService(conn db.TxBeginner) *Service {
	return &Service{db: conn}
}

// Created is returned once, when a key is made. Secret is the full key.
type Created struct {
	Key    sqlc.ApiKey
	Secret string
}

// Create issues a new key for the caller's tenant. A key can be "member" or
// "admin", never "owner", and never more powerful than its creator.
func (s *Service) Create(ctx context.Context, caller auth.Claims, name, role string) (Created, error) {
	if role != auth.RoleMember && role != auth.RoleAdmin {
		return Created{}, ErrRoleNotAllowed
	}
	if !auth.HasRole(caller.Role, role) {
		return Created{}, ErrRoleNotAllowed
	}

	secret, err := randomSecret()
	if err != nil {
		return Created{}, err
	}
	raw := formatKey(caller.TenantID, secret)

	var key sqlc.ApiKey
	err = db.WithTenantTx(ctx, s.db, caller.TenantID, func(tx pgx.Tx) error {
		var err error
		key, err = sqlc.New(tx).CreateAPIKey(ctx, sqlc.CreateAPIKeyParams{
			TenantID:  caller.TenantID,
			Name:      strings.TrimSpace(name),
			Prefix:    auth.APIKeyPrefix + secret[:hintLen],
			KeyHash:   hashKey(raw),
			Role:      role,
			CreatedBy: caller.UserID,
		})
		return err
	})
	if err != nil {
		return Created{}, fmt.Errorf("creating API key: %w", err)
	}
	return Created{Key: key, Secret: raw}, nil
}

// List returns the tenant's keys, newest first. The rows include KeyHash;
// callers must never send it to clients.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]sqlc.ApiKey, error) {
	var keys []sqlc.ApiKey
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		var err error
		keys, err = sqlc.New(tx).ListAPIKeys(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("listing API keys: %w", err)
	}
	return keys, nil
}

// Revoke disables a key immediately. Revoking twice, or another tenant's key,
// is "not found".
func (s *Service) Revoke(ctx context.Context, tenantID, id uuid.UUID) error {
	var n int64
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		var err error
		n, err = sqlc.New(tx).RevokeAPIKey(ctx, id)
		return err
	})
	if err != nil {
		return fmt.Errorf("revoking API key: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Verify checks a presented key and returns the claims it grants. Every
// rejection is auth.ErrInvalidAPIKey; any other error is an internal failure.
func (s *Service) Verify(ctx context.Context, raw string) (auth.Claims, error) {
	tenantID, ok := parseKey(raw)
	if !ok {
		return auth.Claims{}, auth.ErrInvalidAPIKey
	}

	var claims auth.Claims
	err := db.WithTenantTx(ctx, s.db, tenantID, func(tx pgx.Tx) error {
		q := sqlc.New(tx)

		key, err := q.GetAPIKeyByHash(ctx, hashKey(raw))
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.ErrInvalidAPIKey
		}
		if err != nil {
			return fmt.Errorf("finding API key: %w", err)
		}
		if key.RevokedAt.Valid {
			return auth.ErrInvalidAPIKey
		}

		tenant, err := q.GetTenantByID(ctx, key.TenantID)
		if err != nil {
			return fmt.Errorf("finding tenant: %w", err)
		}
		if tenant.Status != "active" {
			return auth.ErrInvalidAPIKey
		}

		if err := q.TouchAPIKey(ctx, key.ID); err != nil {
			return fmt.Errorf("recording API key use: %w", err)
		}

		claims = auth.Claims{
			UserID:   key.CreatedBy,
			TenantID: key.TenantID,
			Role:     key.Role,
			APIKeyID: key.ID,
		}
		return nil
	})
	if err != nil {
		return auth.Claims{}, err
	}
	return claims, nil
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating API key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func formatKey(tenantID uuid.UUID, secret string) string {
	return auth.APIKeyPrefix + hex.EncodeToString(tenantID[:]) + "_" + secret
}

// parseKey extracts the tenant ID. The secret part is base64url and may itself
// contain "_", so only the first "_" after the tenant part is a separator.
func parseKey(raw string) (uuid.UUID, bool) {
	rest, ok := strings.CutPrefix(raw, auth.APIKeyPrefix)
	if !ok {
		return uuid.Nil, false
	}
	tenantHex, secret, ok := strings.Cut(rest, "_")
	if !ok || len(tenantHex) != 32 || secret == "" {
		return uuid.Nil, false
	}
	b, err := hex.DecodeString(tenantHex)
	if err != nil {
		return uuid.Nil, false
	}
	id, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// hashKey is SHA-256: the key holds 256 random bits, so there is nothing to
// brute-force, and lookups need an exact, fast match.
func hashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
