// Package ratelimit protects shared capacity from noisy tenants using a
// token bucket stored in Redis.
//
// Analogy: each tenant owns a bucket that holds up to Burst tokens. Every
// request takes one token out. The bucket refills at Rate tokens per second.
// An empty bucket means "slow down" (HTTP 429).
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limit is one tenant's allowance.
type Limit struct {
	Rate  float64 // tokens added per second
	Burst int     // bucket size: the most requests allowed at once
}

// Result describes the outcome of one Allow call.
type Result struct {
	Allowed    bool
	Remaining  int           // whole tokens left after this request
	RetryAfter time.Duration // how long until a token is available (0 if allowed)
}

// Limiter decides whether a key (here: a tenant) may make a request now.
type Limiter interface {
	Allow(ctx context.Context, key string, l Limit) (Result, error)
}

// tokenBucketScript runs atomically inside Redis, so two app servers can never
// race on the same bucket. It uses Redis's own clock (TIME) so servers with
// slightly different clocks still agree.
//
// KEYS[1] bucket key; ARGV[1] rate/sec, ARGV[2] burst.
// Returns {allowed (0/1), remaining tokens, retry-after in milliseconds}.
var tokenBucketScript = redis.NewScript(`
local rate  = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = burst
  ts = now
end

local elapsed = math.max(0, now - ts)
tokens = math.min(burst, tokens + elapsed * rate / 1000)

local allowed = 0
local retry = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry = math.ceil((1 - tokens) / rate * 1000)
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
-- Idle buckets expire on their own once they would be full again.
redis.call('PEXPIRE', KEYS[1], math.ceil(burst / rate * 1000) + 1000)
return {allowed, math.floor(tokens), retry}
`)

// Redis is a Limiter backed by Redis.
type Redis struct {
	client redis.Scripter
	prefix string
}

// NewRedis returns a Redis-backed limiter. Keys are stored as prefix+key.
func NewRedis(client redis.Scripter, prefix string) *Redis {
	return &Redis{client: client, prefix: prefix}
}

// Allow takes one token from key's bucket if available.
func (r *Redis) Allow(ctx context.Context, key string, l Limit) (Result, error) {
	if l.Rate <= 0 || l.Burst < 1 {
		return Result{}, fmt.Errorf("invalid limit %+v: rate and burst must be positive", l)
	}
	raw, err := tokenBucketScript.Run(ctx, r.client, []string{r.prefix + key}, l.Rate, l.Burst).Slice()
	if err != nil {
		return Result{}, fmt.Errorf("running token bucket: %w", err)
	}
	if len(raw) != 3 {
		return Result{}, fmt.Errorf("unexpected token bucket reply: %v", raw)
	}
	allowed, _ := raw[0].(int64)
	remaining, _ := raw[1].(int64)
	retryMs, _ := raw[2].(int64)
	return Result{
		Allowed:    allowed == 1,
		Remaining:  int(remaining),
		RetryAfter: time.Duration(retryMs) * time.Millisecond,
	}, nil
}
