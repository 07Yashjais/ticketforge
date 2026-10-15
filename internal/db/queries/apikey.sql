-- name: CreateAPIKey :one
INSERT INTO api_keys (tenant_id, name, prefix, key_hash, role, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListAPIKeys :many
SELECT * FROM api_keys ORDER BY created_at DESC, id DESC;

-- name: RevokeAPIKey :execrows
UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys WHERE key_hash = $1;

-- Record usage at most once a minute per key, so a busy integration does not
-- turn every read into a write.
-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');
