// Package config loads application settings from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// Config holds every runtime setting the app needs.
type Config struct {
	Env      string     // "development" or "production"
	HTTPAddr string     // listen address, e.g. ":8080"
	LogLevel slog.Level // debug, info, warn or error

	// Infrastructure addresses. Not used yet; validated later as each
	// phase starts depending on them. DatabaseURL must be the restricted
	// app role, never the owner, so RLS applies.
	DatabaseURL string
	RedisAddr   string
	SMTPAddr    string

	// MigrationDatabaseURL is the owner role, used only by cmd/migrate to
	// change the schema. The API must never use it (owners bypass RLS).
	MigrationDatabaseURL string

	// JWTSecret signs access tokens. It has no default on purpose: a default
	// secret in source code would let anyone forge tokens. auth.NewTokenManager
	// enforces the minimum length.
	JWTSecret string
}

// Load builds a Config from the given lookup function (use os.Getenv in
// production, a map lookup in tests). Unset variables fall back to safe
// development defaults; invalid values return an error.
func Load(getenv func(string) string) (Config, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}

	cfg := Config{
		Env:         get("APP_ENV", "development"),
		DatabaseURL: get("DATABASE_URL", ""),
		RedisAddr:   get("REDIS_ADDR", "localhost:6379"),
		SMTPAddr:    get("SMTP_ADDR", "localhost:1025"),

		MigrationDatabaseURL: get("MIGRATE_DATABASE_URL", ""),

		JWTSecret: get("JWT_SECRET", ""),
	}

	if cfg.Env != "development" && cfg.Env != "production" {
		return Config{}, fmt.Errorf("APP_ENV must be development or production, got %q", cfg.Env)
	}

	port, err := strconv.Atoi(get("HTTP_PORT", "8080"))
	if err != nil || port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("HTTP_PORT must be a number between 1 and 65535")
	}
	cfg.HTTPAddr = fmt.Sprintf(":%d", port)

	if err := cfg.LogLevel.UnmarshalText([]byte(get("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("invalid LOG_LEVEL: %w", err)
	}

	return cfg, nil
}
