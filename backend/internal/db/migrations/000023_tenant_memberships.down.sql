DROP INDEX IF EXISTS idx_users_email_lookup;
DROP INDEX IF EXISTS idx_users_identity_key;
ALTER TABLE users DROP COLUMN IF EXISTS identity_key;

DROP TABLE IF EXISTS tenant_memberships;
