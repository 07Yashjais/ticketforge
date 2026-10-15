-- name: GetTenantBySubdomain :one
SELECT * FROM tenants WHERE subdomain = $1;

-- name: GetTenantByID :one
SELECT * FROM tenants WHERE id = $1;

-- Matches the lower(email) unique index.
-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower($1);

-- name: GetMembership :one
SELECT * FROM memberships WHERE tenant_id = $1 AND user_id = $2;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (family_id, user_id, tenant_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- Locks the row so two simultaneous refreshes of one token cannot both succeed.
-- name: GetRefreshTokenForUpdate :one
SELECT * FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL;
