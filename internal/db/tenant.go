package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TxBeginner starts a transaction. *pgxpool.Pool satisfies it.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// SetTenant scopes the current transaction to one tenant. Postgres RLS
// policies read this value, so every query in tx only sees that tenant's rows.
//
// The third argument of set_config (true) means "local to this transaction":
// the setting disappears at COMMIT or ROLLBACK. That matters because pooled
// connections are reused by other requests; a session-wide setting would leak
// one tenant's identity into the next request. The tenant ID is passed as a
// query parameter, never concatenated into SQL.
func SetTenant(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("setting tenant: %w", err)
	}
	return nil
}

// WithTenantTx runs fn inside a transaction scoped to tenantID. It commits if
// fn returns nil and rolls back otherwise. This is the only intended way to
// touch tenant-owned tables.
func WithTenantTx(ctx context.Context, db TxBeginner, tenantID uuid.UUID, fn func(tx pgx.Tx) error) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	// After a successful Commit this is a no-op; on any early return it rolls back.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := SetTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}
