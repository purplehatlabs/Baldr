-- JWT invalidation: bump token_version when membership role/status changes
ALTER TABLE tenant_memberships
    ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 1;

-- Workspace invites: join an existing tenant by email token
CREATE TABLE tenant_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email       VARCHAR(255) NOT NULL,
    role        VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    token       VARCHAR(64) NOT NULL UNIQUE,
    invited_by  UUID NOT NULL REFERENCES users(id),
    status      VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ NULL,
    accepted_by UUID NULL REFERENCES users(id)
);

CREATE INDEX idx_tenant_invites_tenant_id ON tenant_invites(tenant_id);
CREATE INDEX idx_tenant_invites_email ON tenant_invites (lower(email));
CREATE INDEX idx_tenant_invites_token ON tenant_invites(token);
CREATE UNIQUE INDEX idx_tenant_invites_pending_email
    ON tenant_invites (tenant_id, lower(email))
    WHERE status = 'pending';
