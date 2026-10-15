-- +goose Up

-- Long-lived refresh tokens. Only a SHA-256 hash is stored, so a database leak
-- does not hand out usable tokens. Tokens rotate on every use; all tokens
-- descended from one login share a family_id, so reuse of an old token can
-- revoke the whole family.
-- Tenant-owned: Row-Level Security decisions for this table are made in Phase 4.
CREATE TABLE refresh_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id  uuid        NOT NULL,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id  uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash text        NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);

-- +goose Down
DROP TABLE refresh_tokens;
