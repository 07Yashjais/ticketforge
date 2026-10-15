package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestReady(t *testing.T) {
	tests := []struct {
		name       string
		pingErr    error
		wantStatus int
		wantBody   string
	}{
		{"database up", nil, http.StatusOK, `"status":"ready"`},
		{"database down", errors.New("dial tcp 10.0.0.5: refused"), http.StatusServiceUnavailable, `"status":"unavailable"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Ready(fakePinger{tt.pingErr})(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tt.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", body, tt.wantBody)
			}
			if strings.Contains(body, "10.0.0.5") {
				t.Fatalf("body leaks the underlying error: %q", body)
			}
		})
	}
}
