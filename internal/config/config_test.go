package config

import (
	"log/slog"
	"testing"
)

func lookup(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(lookup(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "development" || cfg.HTTPAddr != ":8080" || cfg.LogLevel != slog.LevelInfo {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(lookup(map[string]string{
		"APP_ENV":   "production",
		"HTTP_PORT": "9090",
		"LOG_LEVEL": "debug",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "production" || cfg.HTTPAddr != ":9090" || cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := map[string]map[string]string{
		"bad env":        {"APP_ENV": "staging"},
		"port not a num": {"HTTP_PORT": "abc"},
		"port too high":  {"HTTP_PORT": "70000"},
		"port zero":      {"HTTP_PORT": "0"},
		"bad log level":  {"LOG_LEVEL": "loud"},
	}
	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(lookup(env)); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}
