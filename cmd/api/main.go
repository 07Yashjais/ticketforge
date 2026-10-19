package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/07Yashjais/ticketforge/internal/apikey"
	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/config"
	"github.com/07Yashjais/ticketforge/internal/db"
	"github.com/07Yashjais/ticketforge/internal/ratelimit"
	"github.com/07Yashjais/ticketforge/internal/server"
	"github.com/07Yashjais/ticketforge/internal/ticket"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main() {
	// A missing .env file is fine; real environment variables still apply.
	_ = godotenv.Load()

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		// No configured logger yet, so use a plain one to report the failure.
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	pool, err := db.NewPool(context.Background(), cfg.DatabaseURL)
	if err != nil {
		logger.Error("connecting to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	tokens, err := auth.NewTokenManager(cfg.JWTSecret)
	if err != nil {
		logger.Error("setting up tokens", "error", err)
		os.Exit(1)
	}
	authSvc, err := auth.NewService(pool, tokens)
	if err != nil {
		logger.Error("setting up auth service", "error", err)
		os.Exit(1)
	}

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	defer rdb.Close()

	router := server.NewRouter(server.Deps{
		DB:      pool,
		Auth:    authSvc,
		Tokens:  tokens,
		Tickets: ticket.NewService(pool),
		APIKeys: apikey.NewService(pool),
		Limiter: ratelimit.NewRedis(rdb, "rl:"),
		// One flat limit for every tenant for now; plan tiers come later.
		LimitFor: func(auth.Claims) ratelimit.Limit { return ratelimit.Limit{Rate: 10, Burst: 20} },
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second, // guards against slowloris clients
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Cancel ctx on Ctrl+C or SIGTERM so we can shut down cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "addr", srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
	}
}
