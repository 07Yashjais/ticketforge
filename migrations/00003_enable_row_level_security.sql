-- +goose Up

-- The tenant the current transaction acts for, set by the app with
--   SELECT set_config('app.current_tenant', '<uuid>', true)
-- Returns NULL when unset or empty, so an unscoped query matches NO rows
-- (fail closed) instead of raising an error or matching everything.
-- +goose StatementBegin
CREATE FUNCTION app_current_tenant() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT NULLIF(current_setting('app.current_tenant', true), '')::uuid $$;
-- +goose StatementEnd

-- FORCE makes the policy apply to the table owner too, not just other roles.
-- USING filters rows that are read, updated or deleted; WITH CHECK rejects
-- inserted or updated rows that would belong to another tenant.
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON memberships
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON refresh_tokens
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());

-- +goose Down
DROP POLICY tenant_isolation ON refresh_tokens;
ALTER TABLE refresh_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens DISABLE ROW LEVEL SECURITY;

DROP POLICY tenant_isolation ON memberships;
ALTER TABLE memberships NO FORCE ROW LEVEL SECURITY;
ALTER TABLE memberships DISABLE ROW LEVEL SECURITY;

DROP FUNCTION app_current_tenant();
