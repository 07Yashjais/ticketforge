// Command migrate applies database migrations as the owner role.
//
// Usage: go run ./cmd/migrate [up|down|status]   (default: up)
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	"github.com/07Yashjais/ticketforge/internal/config"
	"github.com/07Yashjais/ticketforge/migrations"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/joho/godotenv"
	"github.com/pressly/goose/v3"
)

func main() {
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("migration failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// A missing .env file is fine; real environment variables still apply.
	_ = godotenv.Load()

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.MigrationDatabaseURL == "" {
		return fmt.Errorf("MIGRATE_DATABASE_URL is not set")
	}

	command := "up"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	conn, err := sql.Open("pgx", cfg.MigrationDatabaseURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer conn.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting dialect: %w", err)
	}

	ctx := context.Background()
	switch command {
	case "up":
		return goose.UpContext(ctx, conn, ".")
	case "down":
		return goose.DownContext(ctx, conn, ".")
	case "status":
		return goose.StatusContext(ctx, conn, ".")
	default:
		return fmt.Errorf("unknown command %q (use up, down or status)", command)
	}
}
