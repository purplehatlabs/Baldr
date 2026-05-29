-- GitHub SSO identity fields on users (compatible with existing Google/dev users)
ALTER TABLE users ALTER COLUMN google_id DROP NOT NULL;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS github_user_id BIGINT NULL,
    ADD COLUMN IF NOT EXISTS github_login VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(50) NOT NULL DEFAULT 'google';

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github_user_id ON users(github_user_id) WHERE github_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_github_login ON users(github_login) WHERE github_login IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_auth_provider ON users(auth_provider);

-- Synced GitHub org members (linked to app users when they log in)
CREATE TABLE org_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    github_user_id  BIGINT NOT NULL,
    github_login    VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL DEFAULT '',
    avatar_url      TEXT NOT NULL DEFAULT '',
    user_id         UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, github_user_id)
);

CREATE INDEX idx_org_members_org_id ON org_members(org_id);
CREATE INDEX idx_org_members_tenant_id ON org_members(tenant_id);
CREATE INDEX idx_org_members_github_user_id ON org_members(github_user_id);
CREATE INDEX idx_org_members_user_id ON org_members(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_org_members_github_login ON org_members(org_id, github_login);

-- Team membership derived from GitHub teams
CREATE TABLE team_members (
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    org_member_id   UUID NOT NULL REFERENCES org_members(id) ON DELETE CASCADE,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, org_member_id)
);

CREATE INDEX idx_team_members_org_member_id ON team_members(org_member_id);

-- Link existing org_members to users by github_user_id (no-op until sync populates org_members)
UPDATE org_members om
SET user_id = u.id
FROM users u
WHERE om.user_id IS NULL
  AND u.github_user_id IS NOT NULL
  AND u.github_user_id = om.github_user_id
  AND u.tenant_id = om.tenant_id;
