-- Multi-tenant RBAC: per-tenant memberships with global user identity
CREATE TABLE tenant_memberships (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    status     VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id)
);

CREATE INDEX idx_tenant_memberships_user_id ON tenant_memberships(user_id);
CREATE INDEX idx_tenant_memberships_tenant_id ON tenant_memberships(tenant_id);
CREATE INDEX idx_tenant_memberships_tenant_status ON tenant_memberships(tenant_id, status);

-- Global identity compatibility: explicit identity key for future tenant switching.
-- Keep legacy users.email uniqueness for backward compatibility in this phase.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS identity_key TEXT GENERATED ALWAYS AS (
        CASE
            WHEN github_user_id IS NOT NULL THEN 'github:' || github_user_id::text
            WHEN google_id IS NOT NULL AND btrim(google_id) <> '' THEN 'google:' || google_id
            WHEN auth_provider = 'dev' THEN 'dev:' || lower(email)
            ELSE 'email:' || lower(email)
        END
    ) STORED;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_identity_key ON users (identity_key);
CREATE INDEX IF NOT EXISTS idx_users_email_lookup ON users (lower(email));

-- Backfill memberships from legacy users.tenant_id + users.role
INSERT INTO tenant_memberships (tenant_id, user_id, role, status, created_at, updated_at)
SELECT tenant_id, id, role, 'active', created_at, created_at
FROM users
ON CONFLICT (tenant_id, user_id) DO NOTHING;
