CREATE TABLE tenant_metrics_daily (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_date           DATE NOT NULL,
    open_critical           INTEGER NOT NULL DEFAULT 0,
    open_high               INTEGER NOT NULL DEFAULT 0,
    open_total              INTEGER NOT NULL DEFAULT 0,
    mttr_high_plus_hours    NUMERIC(10,2) NOT NULL DEFAULT 0,
    sla_breach_rate         NUMERIC(6,4) NOT NULL DEFAULT 0,
    scan_coverage_rate      NUMERIC(6,4) NOT NULL DEFAULT 0,
    critical_without_owner  INTEGER NOT NULL DEFAULT 0,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, snapshot_date)
);

CREATE TABLE repo_metrics_daily (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    repo_id        UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    snapshot_date  DATE NOT NULL,
    open_critical  INTEGER NOT NULL DEFAULT 0,
    open_high      INTEGER NOT NULL DEFAULT 0,
    open_total     INTEGER NOT NULL DEFAULT 0,
    new_findings   INTEGER NOT NULL DEFAULT 0,
    fixed_findings INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, repo_id, snapshot_date)
);

CREATE TABLE team_metrics_daily (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    team_id        UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    snapshot_date  DATE NOT NULL,
    open_critical  INTEGER NOT NULL DEFAULT 0,
    open_high      INTEGER NOT NULL DEFAULT 0,
    open_total     INTEGER NOT NULL DEFAULT 0,
    new_findings   INTEGER NOT NULL DEFAULT 0,
    fixed_findings INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, team_id, snapshot_date)
);

CREATE INDEX idx_tenant_metrics_daily_tenant_date
    ON tenant_metrics_daily (tenant_id, snapshot_date DESC);

CREATE INDEX idx_repo_metrics_daily_tenant_date
    ON repo_metrics_daily (tenant_id, snapshot_date DESC);

CREATE INDEX idx_repo_metrics_daily_tenant_repo_date
    ON repo_metrics_daily (tenant_id, repo_id, snapshot_date DESC);

CREATE INDEX idx_team_metrics_daily_tenant_date
    ON team_metrics_daily (tenant_id, snapshot_date DESC);

CREATE INDEX idx_team_metrics_daily_tenant_team_date
    ON team_metrics_daily (tenant_id, team_id, snapshot_date DESC);
