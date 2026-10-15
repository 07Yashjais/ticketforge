//go:build integration

// Package test holds integration tests that run against a real PostgreSQL
// started by testcontainers. Run them with:
//
//	go test -tags=integration ./test/...
//
// Docker must be running. They are behind a build tag so that a plain
// `go test ./...` stays fast and needs no Docker.
package test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/07Yashjais/ticketforge/internal/db"
	"github.com/07Yashjais/ticketforge/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	dbName      = "ticketforge"
	ownerUser   = "owner"
	ownerPass   = "owner_pw"
	appUser     = "ticketforge_app"
	appPassword = "app_pw"
)

var (
	ownerPool *pgxpool.Pool // superuser: seeding and inspection only (bypasses RLS)
	appPool   *pgxpool.Pool // restricted role: the same kind of user the API uses
	appURL    string
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase(dbName),
		tcpostgres.WithUsername(ownerUser),
		tcpostgres.WithPassword(ownerPass),
		// Postgres starts, runs init, then restarts; it is only really ready
		// the second time it logs this line.
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		log.Printf("starting postgres container (is Docker running?): %v", err)
		return 1
	}
	defer func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			log.Printf("terminating container: %v", err)
		}
	}()

	ownerURL, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Printf("connection string: %v", err)
		return 1
	}
	u, err := url.Parse(ownerURL)
	if err != nil {
		log.Printf("parsing connection string: %v", err)
		return 1
	}
	u.User = url.UserPassword(appUser, appPassword)
	appURL = u.String()

	if ownerPool, err = db.NewPool(ctx, ownerURL); err != nil {
		log.Printf("owner pool: %v", err)
		return 1
	}
	defer ownerPool.Close()

	// Mirror docker/postgres/init/01-app-role.sh. The role and default
	// privileges must exist BEFORE the migrations create the tables.
	if _, err := ownerPool.Exec(ctx, fmt.Sprintf(`
		CREATE ROLE %[1]s LOGIN PASSWORD '%[2]s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
		GRANT CONNECT ON DATABASE %[3]s TO %[1]s;
		GRANT USAGE ON SCHEMA public TO %[1]s;
		ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %[1]s;
		ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %[1]s;`,
		appUser, appPassword, dbName)); err != nil {
		log.Printf("creating app role: %v", err)
		return 1
	}

	if err := migrate(ownerURL); err != nil {
		log.Printf("migrating: %v", err)
		return 1
	}

	if appPool, err = db.NewPool(ctx, appURL); err != nil {
		log.Printf("app pool: %v", err)
		return 1
	}
	defer appPool.Close()

	return m.Run()
}

func migrate(ownerURL string) error {
	conn, err := sql.Open("pgx", ownerURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(conn, ".")
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}
