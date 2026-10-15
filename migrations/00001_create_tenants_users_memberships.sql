-- +goose Up

-- A tenant is one company using the app.
CREATE TABLE tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    subdomain  text        NOT NULL UNIQUE CHECK (subdomain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    plan       text        NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
    status     text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- A user is a person. One user can belong to many tenants (see memberships).
CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text        NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    password_hash text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Emails are unique ignoring case, so Alice@x.com and alice@x.com are one user.
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

-- Links a user to a tenant with a role.
-- Tenant-owned: Row-Level Security is added to this table in Phase 4.
CREATE TABLE memberships (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text        NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);

-- The UNIQUE constraint indexes (tenant_id, user_id); this serves "which tenants is this user in?".
CREATE INDEX memberships_user_id_idx ON memberships (user_id);

-- +goose Down
DROP TABLE memberships;
DROP TABLE users;
DROP TABLE tenants;
