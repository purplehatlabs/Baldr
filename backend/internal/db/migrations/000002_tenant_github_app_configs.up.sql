CREATE TABLE tenant_github_app_configs (
    tenant_id             UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    app_id                BIGINT NOT NULL,
    private_key_encrypted BYTEA NOT NULL,
    updated_by_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
