CREATE TABLE finding_analyses (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id              UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_job_id             UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,

    analysis_status         VARCHAR(50) NOT NULL DEFAULT 'pending'
                            CHECK (analysis_status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    trigger_source          VARCHAR(50) NOT NULL DEFAULT 'scan'
                            CHECK (trigger_source IN ('scan', 'manual')),

    criticality_verdict     VARCHAR(50),
    exploitability_verdict  VARCHAR(50),
    confidence              NUMERIC(3, 2),
    reasoning               TEXT NOT NULL DEFAULT '',
    exploitation_path       TEXT NOT NULL DEFAULT '',
    remediation_path        TEXT NOT NULL DEFAULT '',

    model_name              VARCHAR(100),
    prompt_version          VARCHAR(50),
    input_hash              VARCHAR(64),
    error_msg               TEXT,

    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_finding_analyses_finding_id ON finding_analyses(finding_id);
CREATE INDEX idx_finding_analyses_tenant_status ON finding_analyses(tenant_id, analysis_status);
CREATE INDEX idx_finding_analyses_finding_created ON finding_analyses(finding_id, created_at DESC);
