//go:build integration

package test

import (
	"testing"

	"github.com/07Yashjais/ticketforge/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Guard: every table with a tenant_id column must have RLS enabled, forced,
// and at least one policy. A new tenant table added without RLS fails here.
func TestEveryTenantTableHasForcedRLS(t *testing.T) {
	rows, err := ownerPool.Query(testCtx(t), `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		       EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		  AND EXISTS (SELECT 1 FROM information_schema.columns col
		              WHERE col.table_schema = 'public'
		                AND col.table_name = c.relname
		                AND col.column_name = 'tenant_id')`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var enabled, forced, hasPolicy bool
		if err := rows.Scan(&name, &enabled, &forced, &hasPolicy); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[name] = true
		if !enabled || !forced || !hasPolicy {
			t.Errorf("table %s: rls enabled=%v forced=%v policy=%v, want all true", name, enabled, forced, hasPolicy)
		}
	}
	for _, want := range []string{"memberships", "refresh_tokens"} {
		if !seen[want] {
			t.Errorf("expected tenant table %s was not found; the guard query may be broken", want)
		}
	}
}

// If the API role could bypass RLS, every other isolation test would pass for
// the wrong reason.
func TestAppRoleCannotBypassRLS(t *testing.T) {
	var super, bypass bool
	err := appPool.QueryRow(testCtx(t),
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if super || bypass {
		t.Fatalf("app role must not be superuser (%v) or bypass RLS (%v)", super, bypass)
	}
}

func TestNoTenantContextSeesNothing(t *testing.T) {
	svc := newAuthService(t)
	signupTenant(t, svc, "a")

	var total, visible int
	if err := ownerPool.QueryRow(testCtx(t), `SELECT count(*) FROM memberships`).Scan(&total); err != nil {
		t.Fatalf("owner count: %v", err)
	}
	if err := appPool.QueryRow(testCtx(t), `SELECT count(*) FROM memberships`).Scan(&visible); err != nil {
		t.Fatalf("app count: %v", err)
	}
	if total == 0 {
		t.Fatal("test setup: no memberships exist")
	}
	if visible != 0 {
		t.Fatalf("query with no tenant set saw %d of %d rows; want 0 (fail closed)", visible, total)
	}
}

func TestTenantSeesOnlyItsOwnRows(t *testing.T) {
	svc := newAuthService(t)
	a := signupTenant(t, svc, "a")
	b := signupTenant(t, svc, "b")

	var tenantIDs []uuid.UUID
	err := db.WithTenantTx(testCtx(t), appPool, a.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(testCtx(t), `SELECT tenant_id FROM memberships`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			tenantIDs = append(tenantIDs, id)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("query as A: %v", err)
	}
	if len(tenantIDs) != 1 || tenantIDs[0] != a.TenantID {
		t.Fatalf("tenant A saw %v, want only [%s]", tenantIDs, a.TenantID)
	}

	// Asking for B's rows by ID, as A, is "not found", not "forbidden".
	var count int
	err = db.WithTenantTx(testCtx(t), appPool, a.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(testCtx(t), `SELECT count(*) FROM memberships WHERE tenant_id = $1 OR user_id = $2`,
			b.TenantID, b.UserID).Scan(&count)
	})
	if err != nil || count != 0 {
		t.Fatalf("A looking up B's membership: count=%d err=%v, want 0, nil", count, err)
	}
}

func TestTenantCannotWriteAnotherTenantsRows(t *testing.T) {
	svc := newAuthService(t)
	a := signupTenant(t, svc, "a")
	b := signupTenant(t, svc, "b")
	ctx := testCtx(t)

	err := db.WithTenantTx(ctx, appPool, a.TenantID, func(tx pgx.Tx) error {
		upd, err := tx.Exec(ctx, `UPDATE memberships SET role = 'member' WHERE tenant_id = $1`, b.TenantID)
		if err != nil {
			return err
		}
		if upd.RowsAffected() != 0 {
			t.Errorf("A updated %d of B's rows, want 0", upd.RowsAffected())
		}

		del, err := tx.Exec(ctx, `DELETE FROM memberships WHERE tenant_id = $1`, b.TenantID)
		if err != nil {
			return err
		}
		if del.RowsAffected() != 0 {
			t.Errorf("A deleted %d of B's rows, want 0", del.RowsAffected())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("update/delete as A: %v", err)
	}

	// Inserting a row that belongs to B while acting as A must be rejected.
	err = db.WithTenantTx(ctx, appPool, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, 'owner')`,
			b.TenantID, a.UserID)
		return err
	})
	var pgErr *pgconn.PgError
	if err == nil {
		t.Fatal("A inserted a membership for tenant B; RLS WITH CHECK did not stop it")
	}
	if !asPgError(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("insert error = %v, want SQLSTATE 42501 (RLS violation)", err)
	}

	// B's data is untouched (checked as the owner, which bypasses RLS).
	var role string
	if err := ownerPool.QueryRow(ctx,
		`SELECT role FROM memberships WHERE tenant_id = $1`, b.TenantID).Scan(&role); err != nil || role != "owner" {
		t.Fatalf("B's membership: role=%q err=%v, want owner, nil", role, err)
	}
}

// SET LOCAL must end with the transaction. With a one-connection pool, the next
// query reuses the same connection that just served tenant A.
func TestTenantContextDoesNotLeakAcrossPooledConnections(t *testing.T) {
	svc := newAuthService(t)
	a := signupTenant(t, svc, "a")

	cfg, err := pgxpool.ParseConfig(appURL)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.MaxConns = 1
	one, err := pgxpool.NewWithConfig(testCtx(t), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(one.Close)

	var inside int
	err = db.WithTenantTx(testCtx(t), one, a.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(testCtx(t), `SELECT count(*) FROM memberships`).Scan(&inside)
	})
	if err != nil || inside == 0 {
		t.Fatalf("inside tenant tx: count=%d err=%v, want >0, nil", inside, err)
	}

	var after int
	if err := one.QueryRow(testCtx(t), `SELECT count(*) FROM memberships`).Scan(&after); err != nil {
		t.Fatalf("after: %v", err)
	}
	if after != 0 {
		t.Fatalf("a later query on the same connection saw %d rows; tenant context leaked", after)
	}
}
