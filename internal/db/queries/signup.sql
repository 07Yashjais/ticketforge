-- name: CreateTenant :one
INSERT INTO tenants (name, subdomain)
VALUES ($1, $2)
RETURNING *;

-- name: CreateUser :one
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING *;

-- name: CreateMembership :one
INSERT INTO memberships (tenant_id, user_id, role)
VALUES ($1, $2, $3)
RETURNING *;
