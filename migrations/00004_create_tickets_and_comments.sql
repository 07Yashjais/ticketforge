-- +goose Up

CREATE TABLE tickets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    title       text        NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    description text        NOT NULL DEFAULT '' CHECK (length(description) <= 10000),
    status      text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
    priority    text        NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    created_by  uuid        NOT NULL REFERENCES users (id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    -- Lets comments point at (ticket, tenant) together; see comments below.
    UNIQUE (id, tenant_id)
);

-- Serves the list endpoint: one tenant's tickets, newest first, keyset-paginated.
CREATE INDEX tickets_tenant_created_idx ON tickets (tenant_id, created_at DESC, id DESC);
CREATE INDEX tickets_tenant_status_idx ON tickets (tenant_id, status);

CREATE TABLE comments (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    ticket_id  uuid        NOT NULL,
    author_id  uuid        NOT NULL REFERENCES users (id),
    body       text        NOT NULL CHECK (length(body) BETWEEN 1 AND 10000),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Defense in depth behind RLS: a comment can only reference a ticket of
    -- the SAME tenant, so even a buggy insert cannot attach a comment across tenants.
    FOREIGN KEY (ticket_id, tenant_id) REFERENCES tickets (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX comments_ticket_created_idx ON comments (ticket_id, created_at, id);

ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tickets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tickets
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());

ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON comments
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());

-- +goose Down
DROP TABLE comments;
DROP TABLE tickets;
