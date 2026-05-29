CREATE TABLE policies (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name               VARCHAR(255) NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    is_enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE policy_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id   UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    rule_type   VARCHAR(100) NOT NULL,
    field       VARCHAR(100) NOT NULL,
    operator    VARCHAR(50) NOT NULL,
    value_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE finding_exceptions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id           UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    reason               TEXT NOT NULL,
    expires_at           TIMESTAMPTZ,
    approved_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE finding_audit_logs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id       UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action           VARCHAR(100) NOT NULL,
    previous_status  VARCHAR(50),
    new_status       VARCHAR(50),
    actor_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE saved_views (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    filters     JSONB NOT NULL DEFAULT '{}'::jsonb,
    sort        VARCHAR(50) NOT NULL DEFAULT 'last_seen_at',
    "order"     VARCHAR(4) NOT NULL DEFAULT 'desc' CHECK ("order" IN ('asc', 'desc')),
    page_size   INTEGER NOT NULL DEFAULT 50,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE integration_configs (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    integration_type   VARCHAR(100) NOT NULL,
    is_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    config_json        JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, integration_type)
);

CREATE INDEX idx_policies_tenant_id ON policies (tenant_id);
CREATE INDEX idx_policy_rules_tenant_policy ON policy_rules (tenant_id, policy_id);
CREATE INDEX idx_finding_exceptions_tenant_finding ON finding_exceptions (tenant_id, finding_id);
CREATE INDEX idx_finding_exceptions_expires_at ON finding_exceptions (expires_at);
CREATE INDEX idx_finding_audit_logs_tenant_finding_created
    ON finding_audit_logs (tenant_id, finding_id, created_at DESC);
CREATE INDEX idx_saved_views_tenant_user ON saved_views (tenant_id, user_id);
CREATE INDEX idx_integration_configs_tenant_type ON integration_configs (tenant_id, integration_type);
