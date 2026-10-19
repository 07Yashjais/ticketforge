//go:build integration

package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// newRedis starts a throwaway Redis and returns a limiter on it.
func newRedis(t *testing.T) *Redis {
	t.Helper()
	ctx := context.Background()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("starting redis: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	addr, err := ctr.PortEndpoint(ctx, "6379/tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedis(client, "test:")
}

func TestRedisTokenBucket(t *testing.T) {
	l := newRedis(t)
	ctx := context.Background()
	limit := Limit{Rate: 2, Burst: 3} // 3 at once, then 2 per second

	// The burst is allowed...
	for i := 0; i < 3; i++ {
		res, err := l.Allow(ctx, "acme", limit)
		if err != nil || !res.Allowed {
			t.Fatalf("request %d: allowed=%v err=%v, want allowed", i, res.Allowed, err)
		}
	}
	// ...the 4th is refused with a sensible wait.
	res, err := l.Allow(ctx, "acme", limit)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed || res.RetryAfter <= 0 || res.RetryAfter > time.Second {
		t.Fatalf("4th request: %+v, want blocked with 0 < RetryAfter <= 1s", res)
	}

	// Another tenant has its own full bucket (noisy-neighbour protection).
	if res, _ := l.Allow(ctx, "globex", limit); !res.Allowed {
		t.Fatal("globex must not be affected by acme's traffic")
	}

	// After the refill time, acme may go again.
	time.Sleep(700 * time.Millisecond)
	if res, _ := l.Allow(ctx, "acme", limit); !res.Allowed {
		t.Fatal("acme should have refilled at least one token")
	}
}

func TestRedisRejectsInvalidLimit(t *testing.T) {
	l := NewRedis(redis.NewClient(&redis.Options{Addr: "localhost:1"}), "x:")
	if _, err := l.Allow(context.Background(), "k", Limit{}); err == nil {
		t.Fatal("expected error for zero limit")
	}
}
