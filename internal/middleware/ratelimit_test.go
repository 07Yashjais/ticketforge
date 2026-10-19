package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/07Yashjais/ticketforge/internal/ratelimit"
	"github.com/google/uuid"
)

// fakeLimiter records the key it was asked about and returns a canned answer.
type fakeLimiter struct {
	res  ratelimit.Result
	err  error
	keys []string
}

func (f *fakeLimiter) Allow(_ context.Context, key string, _ ratelimit.Limit) (ratelimit.Result, error) {
	f.keys = append(f.keys, key)
	return f.res, f.err
}

func serve(t *testing.T, l ratelimit.Limiter, claims auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	h := RateLimit(l, func(auth.Claims) ratelimit.Limit { return ratelimit.Limit{Rate: 1, Burst: 5} })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, claims))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && !called {
		t.Fatal("handler not called on 200")
	}
	return rec
}

func TestRateLimit_AllowsAndSetsHeaders(t *testing.T) {
	f := &fakeLimiter{res: ratelimit.Result{Allowed: true, Remaining: 4}}
	rec := serve(t, f, auth.Claims{TenantID: uuid.New()})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "4" || rec.Header().Get("X-RateLimit-Limit") != "5" {
		t.Errorf("bad headers: %v", rec.Header())
	}
}

func TestRateLimit_Blocks429WithRetryAfter(t *testing.T) {
	f := &fakeLimiter{res: ratelimit.Result{Allowed: false, RetryAfter: 1500 * time.Millisecond}}
	rec := serve(t, f, auth.Claims{TenantID: uuid.New()})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want 2 (1.5s rounded up)", got)
	}
}

func TestRateLimit_KeyedByTenant(t *testing.T) {
	f := &fakeLimiter{res: ratelimit.Result{Allowed: true}}
	tenant := uuid.New()
	serve(t, f, auth.Claims{TenantID: tenant, UserID: uuid.New()})
	serve(t, f, auth.Claims{TenantID: tenant, UserID: uuid.New()})
	if len(f.keys) != 2 || f.keys[0] != f.keys[1] || f.keys[0] != "tenant:"+tenant.String() {
		t.Errorf("users of one tenant must share one bucket, keys = %v", f.keys)
	}
}

func TestRateLimit_FailsOpenWhenLimiterErrors(t *testing.T) {
	f := &fakeLimiter{err: errors.New("redis down")}
	rec := serve(t, f, auth.Claims{TenantID: uuid.New()})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (fail open)", rec.Code)
	}
}

func TestRateLimit_WithoutAuthIs500(t *testing.T) {
	h := RateLimit(&fakeLimiter{}, func(auth.Claims) ratelimit.Limit { return ratelimit.Limit{Rate: 1, Burst: 1} })(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500", rec.Code)
	}
}
