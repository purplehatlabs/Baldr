DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS org_members;

DROP INDEX IF EXISTS idx_users_auth_provider;
DROP INDEX IF EXISTS idx_users_github_login;
DROP INDEX IF EXISTS idx_users_github_user_id;

ALTER TABLE users
    DROP COLUMN IF EXISTS auth_provider,
    DROP COLUMN IF EXISTS github_login,
    DROP COLUMN IF EXISTS github_user_id;

-- Restore NOT NULL on google_id (only safe if no NULL values exist)
UPDATE users SET google_id = 'legacy:' || id::text WHERE google_id IS NULL;
ALTER TABLE users ALTER COLUMN google_id SET NOT NULL;
