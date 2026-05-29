DROP TABLE IF EXISTS tenant_invites;

ALTER TABLE tenant_memberships
    DROP COLUMN IF EXISTS token_version;
