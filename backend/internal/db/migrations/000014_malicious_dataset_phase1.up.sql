CREATE TABLE malicious_package_indicators (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source           VARCHAR(100) NOT NULL DEFAULT 'openssf',
    external_id      VARCHAR(255) NOT NULL,
    ecosystem        VARCHAR(100) NOT NULL,
    package_name     VARCHAR(500) NOT NULL,
    package_version  VARCHAR(255) NOT NULL DEFAULT '',
    summary          TEXT NOT NULL DEFAULT '',
    details          TEXT NOT NULL DEFAULT '',
    published_at     TIMESTAMPTZ,
    modified_at      TIMESTAMPTZ,
    withdrawn_at     TIMESTAMPTZ,
    references_json  JSONB NOT NULL DEFAULT '[]'::jsonb,
    affected_json    JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_json         JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source, external_id, ecosystem, package_name, package_version)
);

CREATE INDEX idx_malicious_indicators_external_id
    ON malicious_package_indicators (external_id);

CREATE INDEX idx_malicious_indicators_pkg
    ON malicious_package_indicators (ecosystem, package_name);

CREATE INDEX idx_malicious_indicators_last_synced
    ON malicious_package_indicators (last_synced_at DESC);

CREATE TABLE package_inventory (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    repo_id            UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    manifest_id        UUID REFERENCES manifests(id) ON DELETE SET NULL,
    finding_id         UUID REFERENCES findings(id) ON DELETE SET NULL,
    ecosystem          VARCHAR(100) NOT NULL,
    package_name       VARCHAR(500) NOT NULL,
    package_version    VARCHAR(255) NOT NULL,
    dependency_scope   VARCHAR(50) NOT NULL DEFAULT 'unknown'
                     CHECK (dependency_scope IN ('direct', 'transitive', 'unknown')),
    source             VARCHAR(50) NOT NULL DEFAULT 'scan'
                     CHECK (source IN ('scan', 'sbom', 'manual')),
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, repo_id, ecosystem, package_name, package_version)
);

CREATE INDEX idx_package_inventory_tenant_repo
    ON package_inventory (tenant_id, repo_id);

CREATE INDEX idx_package_inventory_pkg
    ON package_inventory (tenant_id, ecosystem, package_name);

CREATE INDEX idx_package_inventory_finding_id
    ON package_inventory (finding_id)
    WHERE finding_id IS NOT NULL;

CREATE TABLE supply_chain_signals (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_job_id             UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    repo_id                 UUID REFERENCES repositories(id) ON DELETE SET NULL,
    manifest_id             UUID REFERENCES manifests(id) ON DELETE SET NULL,
    package_inventory_id    UUID REFERENCES package_inventory(id) ON DELETE SET NULL,
    finding_id              UUID REFERENCES findings(id) ON DELETE SET NULL,
    indicator_id            UUID REFERENCES malicious_package_indicators(id) ON DELETE SET NULL,
    signal_type             VARCHAR(50) NOT NULL
                          CHECK (signal_type IN ('malicious_package', 'typosquat', 'dependency_confusion', 'suspicious_behavior')),
    status                  VARCHAR(50) NOT NULL DEFAULT 'open'
                          CHECK (status IN ('open', 'triaged', 'suppressed', 'resolved')),
    severity                VARCHAR(50) NOT NULL DEFAULT 'medium'
                          CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    package_ecosystem       VARCHAR(100) NOT NULL,
    package_name            VARCHAR(500) NOT NULL,
    package_version         VARCHAR(255) NOT NULL DEFAULT '',
    source_engine           VARCHAR(50) NOT NULL
                          CHECK (source_engine IN ('dataset', 'guarddog', 'openssf_pa', 'manual')),
    signal_key              VARCHAR(255) NOT NULL DEFAULT '',
    signal_hash             VARCHAR(128) NOT NULL,
    confidence              NUMERIC(5, 4),
    reasoning               TEXT NOT NULL DEFAULT '',
    evidence_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, signal_hash)
);

CREATE INDEX idx_supply_chain_signals_tenant_status
    ON supply_chain_signals (tenant_id, status, severity);

CREATE INDEX idx_supply_chain_signals_repo_manifest
    ON supply_chain_signals (tenant_id, repo_id, manifest_id);

CREATE INDEX idx_supply_chain_signals_indicator
    ON supply_chain_signals (indicator_id)
    WHERE indicator_id IS NOT NULL;

CREATE INDEX idx_supply_chain_signals_package
    ON supply_chain_signals (tenant_id, package_ecosystem, package_name);

CREATE TABLE package_dynamic_analysis_runs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    signal_id               UUID REFERENCES supply_chain_signals(id) ON DELETE CASCADE,
    package_ecosystem       VARCHAR(100) NOT NULL,
    package_name            VARCHAR(500) NOT NULL,
    package_version         VARCHAR(255) NOT NULL DEFAULT '',
    engine                  VARCHAR(50) NOT NULL
                          CHECK (engine IN ('package_analysis', 'sandbox', 'osv', 'custom')),
    status                  VARCHAR(50) NOT NULL DEFAULT 'queued'
                          CHECK (status IN ('queued', 'running', 'completed', 'failed', 'skipped')),
    verdict                 VARCHAR(50)
                          CHECK (verdict IS NULL OR verdict IN ('malicious', 'suspicious', 'benign', 'inconclusive')),
    risk_score              NUMERIC(7, 4),
    summary                 TEXT NOT NULL DEFAULT '',
    error_msg               TEXT,
    report_json             JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_package_dynamic_runs_tenant_signal_engine
    ON package_dynamic_analysis_runs (tenant_id, signal_id, engine)
    WHERE signal_id IS NOT NULL;

CREATE INDEX idx_package_dynamic_runs_tenant_status
    ON package_dynamic_analysis_runs (tenant_id, status, created_at DESC);

CREATE INDEX idx_package_dynamic_runs_package
    ON package_dynamic_analysis_runs (tenant_id, package_ecosystem, package_name);
