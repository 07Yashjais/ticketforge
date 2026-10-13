package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSONEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		key     string
		want    string
	}{
		{"health", Health, "status", "ok"},
		{"version", VersionInfo, "version", Version},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if body[tt.key] != tt.want {
				t.Fatalf("body[%q] = %q, want %q", tt.key, body[tt.key], tt.want)
			}
		})
	}
}
