CREATE TABLE tenant_llm_configs (
    tenant_id          UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    base_url           TEXT NOT NULL,
    model              TEXT NOT NULL,
    api_key_encrypted  BYTEA,
    timeout_seconds    INTEGER NOT NULL DEFAULT 60 CHECK (timeout_seconds BETWEEN 5 AND 600),
    updated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
