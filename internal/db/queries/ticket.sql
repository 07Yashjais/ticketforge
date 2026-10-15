-- Reads and updates below have no "WHERE tenant_id = ..." on purpose: Postgres
-- RLS adds that filter to every statement. Inserts must name the tenant_id,
-- and RLS WITH CHECK rejects any value other than the current tenant.

-- name: CreateTicket :one
INSERT INTO tickets (tenant_id, title, description, priority, created_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetTicket :one
SELECT * FROM tickets WHERE id = $1;

-- Keyset pagination: pass the last row's (created_at, id) as the cursor.
-- name: ListTickets :many
SELECT * FROM tickets
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('cursor_created_at')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('row_limit');

-- Only the fields that are provided (non-NULL) change.
-- name: UpdateTicket :one
UPDATE tickets SET
    title       = COALESCE(sqlc.narg('title')::text, title),
    description = COALESCE(sqlc.narg('description')::text, description),
    status      = COALESCE(sqlc.narg('status')::text, status),
    priority    = COALESCE(sqlc.narg('priority')::text, priority),
    updated_at  = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: DeleteTicket :execrows
DELETE FROM tickets WHERE id = $1;

-- name: CreateComment :one
INSERT INTO comments (tenant_id, ticket_id, author_id, body)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListComments :many
SELECT * FROM comments WHERE ticket_id = $1 ORDER BY created_at, id;
