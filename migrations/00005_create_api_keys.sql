-- +goose Up

-- API keys let a tenant's own software call the API without a user login.
-- The full key is shown once at creation; only its SHA-256 hash is stored.
-- `prefix` is a short, non-secret slice of the key so people can tell keys
-- apart in a list ("tfk_3f2a…").
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name         text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix       text        NOT NULL,
    key_hash     text        NOT NULL UNIQUE,
    -- A key never gets owner powers.
    role         text        NOT NULL CHECK (role IN ('admin', 'member')),
    created_by   uuid        NOT NULL REFERENCES users (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE INDEX api_keys_tenant_created_idx ON api_keys (tenant_id, created_at DESC);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON api_keys
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());

-- +goose Down
DROP TABLE api_keys;
